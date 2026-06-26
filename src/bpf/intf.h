/* SPDX-License-Identifier: GPL-2.0 */
/* scx_imperator BPF/userspace interface - shared data structures and constants */

#ifndef __CAKE_INTF_H
#define __CAKE_INTF_H

#include <limits.h>

#ifndef __VMLINUX_H__
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;
typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long s64;
#endif

/* CAKE TIER SYSTEM — 4-tier classification by avg_runtime */
enum imperator_tier {
    CAKE_TIER_CRITICAL  = 0,  /* <100µs:  IRQ, input, audio, network */
    CAKE_TIER_INTERACT  = 1,  /* <2ms:    compositor, physics, AI */
    CAKE_TIER_FRAME     = 2,  /* <8ms:    game render, encoding */
    CAKE_TIER_BULK      = 3,  /* ≥8ms:    compilation, background */
    CAKE_TIER_MAX       = 4,
};

#define CAKE_TIER_IDX(t)  ((t) & 7)
_Static_assert(CAKE_TIER_MAX <= 8,
    "CAKE_TIER_MAX exceeds array size — update CAKE_TIER_IDX mask");

#define CAKE_MAX_CPUS 64
#define CAKE_MAX_LLCS 8

#define LLC_DSQ_BASE 200

/* FIX (W13): CAKE_ETD_CROSS_LLC_THRESHOLD removed — defined as 5 but never
 * referenced in BPF or Rust code.  Zero call sites confirmed by static analysis.
 * If a cross-LLC cost threshold is needed in future, reintroduce it here. */

/* FLOW STATE FLAGS */
enum imperator_flow_flags {
    CAKE_FLOW_NEW         = 1 << 0,
    CAKE_FLAG_LOCK_HOLDER = 1 << 1,
    CAKE_FLOW_IRQ_WAKE    = 1 << 2,
};

/* Per-task flow state — 64B, one cache line */
struct imperator_task_ctx {
    /* Hot write group (imperator_stopping) [Bytes 0-15] */
    u64 next_slice;

    union {
        struct {
            union {
                struct {
                    u16 deficit_us;
                    u16 avg_runtime_us;
                };
                u32 deficit_avg_fused;
            };
            u32 packed_info;
        };
        u64 state_fused_u64;
    };

    /* Timestamp (imperator_running) [Bytes 16-19] */
    u32 last_run_at;

    /* Graduated backoff counter [Bytes 20-21] */
    u16 reclass_counter;

    /* S5: overrun_count — 8-bit shift register of execution outcomes.
     *
     * IMPLEMENTED AS: bit-history shift register (imperator_bpf.c [H] s6).
     *
     * SEMANTICS: Each stop, the register shifts left one position and the
     * current bout's result is inserted in the LSB.  The oldest result falls
     * off the MSB.
     *
     *   bit value 1 → that bout's rt_clamped exceeded 1.5× the tier gate
     *   bit value 0 → that bout ran within the gate
     *
     * DEMOTION TRIGGER: __builtin_popcount(overrun_count) >= 4
     *   Fires when 4 of the last 8 bouts exceeded the gate.
     *
     * BEHAVIORAL SUPERSET OF ORIGINAL CONSECUTIVE COUNTER:
     *   4 consecutive overruns → hist = 0b00001111 → popcount = 4 ≥ 4 → DEMOTE
     *   This is identical to the original counter-based trigger at N=4.
     *
     * NEW CAPABILITY (non-consecutive detection):
     *   4 alternating overruns over 8 bouts → popcount = 4 ≥ 4 → DEMOTE
     *   Original counter reset on every normal bout and never fired.
     *   Example: physics thread spiking every other frame for 8 frames.
     *
     * This change is strictly a superset of the original: every pattern that
     * triggered before still triggers; additional patterns now also trigger.
     *
     * THRESHOLD: 4 (not 5 — threshold 5 was a regression: 4 consecutive
     * overruns → popcount=4 < 5 → no demotion, breaking parity with the
     * original consecutive counter that fired at exactly 4).
     *
     * INIT VALUE: 0 (empty history, no overruns observed) — set explicitly
     * by alloc_task_ctx_cold; also reset on exec in imperator_init_task.
     * FIELD NAME: kept as `overrun_count` to avoid disrupting external tools;
     *             the type (u8) and offset (byte 22) are unchanged.
     * STRUCT SIZE: __pad has been reduced from [39] to [28] to accommodate the
     *   C2-Infra fields (enqueue_time u32, jitter_ewma_us u16) and C3 field
     *   (burst_credit u16) plus 3 bytes of explicit alignment padding.  The
     *   struct remains exactly 64B; the _Static_assert below enforces this. */
    u8 overrun_count;

    u8 lock_skip_count;

    /* pending_futex_op — tracepoint fallback op storage (lock_bpf.c).
     *
     * Stores the futex op recorded at sys_enter_futex so sys_exit_futex can
     * act on it even if the task migrated CPUs while sleeping (blocking futex
     * variants park the task inside the kernel and may wake it on a different
     * CPU from where it entered).
     *
     * INIT VALUE: CAKE_FUTEX_OP_UNSET (0xFF) — written explicitly by
     * alloc_task_ctx_cold.  BPF task-storage zero-initialises new entries
     * (giving 0 == CAKE_FUTEX_WAIT), which would cause a false set_lock_holder()
     * on the first sys_exit_futex(ret=0) before any sys_enter_futex is observed.
     * The explicit 0xFF init makes the UNSET guard in imperator_tp_exit_futex safe
     * from the very first syscall. */
    u8 pending_futex_op;  /* byte 24 */

    /* Explicit alignment pad [Bytes 25-27]
     * enqueue_time is u32 and must be 4-byte aligned.  The three bytes between
     * pending_futex_op (byte 24) and enqueue_time (byte 28) would be silently
     * inserted by the compiler as implicit padding; we make them explicit so
     * the _Static_assert below catches any future layout drift.  These bytes
     * are unused and must be zero-initialized with the rest of the struct. */
    u8 __align_pad[3];

    /* C2-Infra: Scheduling latency telemetry [Bytes 28-33]
     *
     * enqueue_time: wall-clock timestamp (u32 ns, truncated from u64, wraps
     *   ~4.3s) written at the start of imperator_enqueue for tasks taking the
     *   standard wakeup/preempt path.  Read in imperator_running to compute
     *   dispatch latency as (last_run_at - enqueue_time).  The subtraction is
     *   safe within u32 for any dispatch latency < 4.3s, which covers all
     *   realistic cases including runaway starvation.  Value 0 means "not yet
     *   stamped via the timed path" and the jitter EWMA update is skipped.
     *   Reset to 0 on exec (imperator_init_task !fork path) and fork.
     *
     * jitter_ewma_us: per-task EWMA of dispatch latency in approximate
     *   microseconds (ns >> 10, same shift as runtime_us throughout the
     *   codebase).  Uses α=1/8 (symmetric) — scheduling latency variance is
     *   not directionally asymmetric in the way runtime is, so the asymmetric
     *   α=1/4 promote / α=1/16 demote used by avg_runtime_us is not appropriate.
     *   Clamped to u16 max (65ms).  Closes W1: first per-task scheduling
     *   latency signal in the scheduler.  Reset to 0 on exec and fork.
     *
     * C3: DRR++ Burst Credit [Bytes 34-35]
     *
     * burst_credit: accumulated preemption-recovery credit in units of
     *   (quantum_ns >> 10) — the same kns units used by deficit_us.  Credited
     *   by (quantum_ns >> 12) kns (= quantum/4) each time this task is
     *   re-enqueued via SCX_ENQ_PREEMPT while in tier T1 or T2, up to the
     *   per-tier cap in tier_burst_cap_kns[].  T0 cap = T3 cap = 0: neither
     *   critical tasks nor bulk tasks receive burst credit.
     *
     *   The credit is accumulated AND consumed within the same imperator_enqueue
     *   invocation: the accumulation block runs first (adding to burst_credit),
     *   then the consumption block reads it, extends the slice, and zeros it.
     *   burst_credit is always 0 when imperator_enqueue returns — it does not
     *   persist between enqueue calls.  A task that is preempted N consecutive
     *   times will extend its slice by min(N × quantum/4, cap) on each
     *   re-dispatch, providing proportional relief against repeated preemptions.
     *
     *   FIX (audit/Finding-4): Previous comment stated "set-on-preemption,
     *   consumed-on-next-dispatch," which was inaccurate.  The correct lifecycle
     *   is "accumulated and consumed within the same enqueue call."
     *
     *   FIX (audit/Finding-5): Previous cap values were {0, 2, 4, 0} in kns,
     *   giving only ~2µs and ~4µs maximum bonus — too small to reduce
     *   rescheduling frequency.  Corrected to {0, 2000, 4000, 0}, giving
     *   T1: ~2ms max bonus (~1× quantum) and T2: ~4ms max bonus (~2× quantum).
     *
     *   FIX (audit/Finding-9): burst_credit is cleared in reclassify_task_cold
     *   whenever the tier changes, preventing stale credit from a higher/lower
     *   tier being consumed after the task has been reclassified.
     *
     *   Lifecycle: zeroed in alloc_task_ctx_cold, exec path of imperator_init_task,
     *   fork path of imperator_init_task, and on every tier change in
     *   reclassify_task_cold.  Always 0 after imperator_enqueue returns.
     *
     * Struct layout [Bytes 24-63]:
     *   [24]     pending_futex_op  (u8)
     *   [25-27]  __align_pad       (u8[3])   alignment gap before u32
     *   [28-31]  enqueue_time      (u32)     C2-Infra: enqueue timestamp
     *   [32-33]  jitter_ewma_us    (u16)     C2-Infra: dispatch latency EWMA
     *   [34-35]  burst_credit      (u16)     C3: preemption burst credit
     *   [36-39]  sleep_entry_time  (u32)     Gap-1: sleep-entry timestamp
     *   [40-63]  __pad             (u8[24])  reserved, zero-initialized
     *
     * Total struct size: 64B — one cache line, _Static_assert enforces this. */
    u32 enqueue_time;      /* bytes 28-31: C2-Infra enqueue timestamp */
    u16 jitter_ewma_us;    /* bytes 32-33: C2-Infra dispatch latency EWMA */
    u16 burst_credit;      /* bytes 34-35: C3 preemption burst credit */

    /* Gap-1 fix: Sleep-duration measurement for post-sleep recovery heuristic.
     *
     * PROBLEM (audit/Finding-6): the previous sleep-recovery heuristic in
     * reclassify_task_cold measured (now - last_run_at) — bout duration, not
     * sleep duration.  A task waking from a 30-second loading-screen sleep
     * after a 5ms bout had runtime_raw=5ms and never triggered the 500ms
     * threshold.  The heuristic almost never fired, regardless of actual sleep
     * time, making it functionally inert.
     *
     * FIX: sleep_entry_time records the wall-clock timestamp (u32 nanoseconds,
     * same truncation as last_run_at and enqueue_time) at the moment a task
     * genuinely blocks — written in imperator_stopping when runnable=false.
     * reclassify_task_cold reads it at wakeup (in imperator_enqueue via the
     * tctx passed at stopping time) to compute actual sleep duration:
     *   sleep_duration = enqueue_time_at_wakeup - sleep_entry_time
     *
     * The subtraction is u32 wrap-safe for any sleep < 4.3 seconds, which
     * covers all gaming and sim loading scenarios.  For sleeps > 4.3s the
     * u32 subtraction wraps, producing an incorrect small value — the heuristic
     * does not fire, which is the same as the previous behavior.  Acceptable:
     * the heuristic is best-effort.
     *
     * LIFECYCLE:
     *   alloc_task_ctx_cold  → sleep_entry_time = 0 (explicit zero)
     *   imperator_stopping   → write (u32)scx_bpf_now() when !runnable
     *                        → write 0 when runnable (clear stale value)
     *   reclassify_task_cold → read and consume (compared against enqueue_time)
     *   imperator_init_task  → reset to 0 on exec and fork
     *
     * SENTINEL: 0 means "no valid sleep entry timestamp" — the heuristic is
     * skipped when sleep_entry_time == 0, matching the enqueue_time pattern.
     *
     * Struct layout [Bytes 36-63]:
     *   [36-39]  sleep_entry_time  (u32)     ← Gap-1 fix
     *   [40-63]  __pad             (u8[24])  reduced from [28] */
    u32 sleep_entry_time;  /* bytes 36-39: sleep-entry timestamp for recovery heuristic */
    u8  __pad[24];         /* bytes 40-63: reserved, reduced from [28] */
} __attribute__((aligned(64)));

_Static_assert(sizeof(struct imperator_task_ctx) == 64,
    "imperator_task_ctx must be exactly 64B (one cache line) — update __pad if fields change");

/* packed_info bitfield layout:
 * [Stable:2][Tier:2][Flags:4][Rsvd:16]
 *  31-30     29-28   27-24    23-0
 *
 * Bits [15:0] previously held WAIT_DATA [15:8] and KALMAN_ERROR [7:0].
 * Both were written (KALMAN_ERROR initialised to 0xFF in alloc_task_ctx_cold)
 * but never read by any scheduling decision in imperator_bpf.c, lock_bpf.c,
 * or the Rust side.  Removed per W2 audit finding.  Bits [23:0] are now
 * reserved (Rsvd) and must be zero except for future use. */
#define SHIFT_FLAGS         24
#define SHIFT_TIER          28
#define SHIFT_STABLE        30

#define MASK_TIER           0x03
#define MASK_FLAGS          0x0F

#define EXTRACT_DEFICIT(fused)  ((u16)((fused) & 0xFFFF))
#define EXTRACT_AVG_RT(fused)   ((u16)((fused) >> 16))
#define PACK_DEFICIT_AVG(deficit, avg)  (((u32)(deficit) & 0xFFFF) | ((u32)(avg) << 16))

/* avg_runtime tier gates (µs) */
#define TIER_GATE_T0   100
#define TIER_GATE_T1   2000
#define TIER_GATE_T2   8000

/* MEGA-MAILBOX */
#define MBOX_TIER_MASK    0x03
#define MBOX_GET_TIER(f)  ((f) & MBOX_TIER_MASK)

/* FIX (W1 / audit): Valid-written sentinel for mega_mailbox flags.
 *
 * PROBLEM: CAKE_TIER_CRITICAL = 0 encodes as flags = 0x00 & MBOX_TIER_MASK = 0x00.
 * BSS zero-initialises the mailbox on scheduler load.  The former guard
 * `cur_mbox_flags != 0` cannot distinguish "never written" from "T0 waker running":
 * both produce flags == 0x00.  Result: waker-tier inheritance is unconditionally
 * suppressed whenever the waker CPU's last task was T0 — exactly the path where
 * a T0 audio thread should be promoting a T2 game thread to T1.
 *
 * FIX: bit 7 of flags is the VALID sentinel.  imperator_running always sets it
 * when writing tier data.  The inheritance guard in imperator_enqueue checks this
 * bit instead of the raw byte value.  T0 wakers now produce flags = 0x80 (valid,
 * tier=0), T1 wakers produce 0x81, T2 produce 0x82 — all non-zero AND valid.
 * The unwritten BSS state (0x00) no longer collides with any real tier value.
 *
 * BACKWARD COMPATIBILITY: MBOX_GET_TIER masks off bit 7 with MBOX_TIER_MASK (0x03)
 * — existing tier extraction is unaffected.  The valid bit is orthogonal. */
#define MBOX_VALID_BIT    7
#define MBOX_VALID_FLAG   (1u << MBOX_VALID_BIT)   /* 0x80 */

struct mega_mailbox_entry {
    u8 flags;
    /* dsq_hint: DVFS perf-target hysteresis cache (u8 = cpuperf_target >> 2).
     * Name is historical (original use was DSQ selection hint, now removed);
     * the field stores the last written DVFS target to skip redundant kfunc
     * calls when the tier has not changed between ticks.
     *
     * Encoding (audit/Finding-2): stores (cpuperf_target >> 2) as u8.
     * cpuperf_target range [0, SCX_CPUPERF_ONE=1024].
     *   T3 Gaming  → target=768  → dsq_hint=192
     *   T0/T1/T2   → target=1024 → dsq_hint=256 → u8=0  (wraps)
     *   Sole-occ.  → target=1024 → dsq_hint=256 → u8=0  (same wrap, correct)
     *   BSS zero   → dsq_hint=0  (same as T0/T1/T2 — first tick always calls kfunc
     *                              because target_cached is also 0 on first read,
     *                              but the kfunc call is idempotent so this is safe)
     *
     * The 0 encoding for SCX_CPUPERF_ONE is deliberate: any transition TO max
     * frequency sets dsq_hint=0; subsequent ticks see cached==target==0 and skip
     * the kfunc call.  The encoding is consistent across all paths that write it.
     *
     * NOTE (perf-regression-guard): an earlier revision of this comment
     * documented a planned T2 target of 896 (dsq_hint=224) that was never
     * applied to tier_perf_target[] in imperator_bpf.c, and a later revision
     * applied it without supporting A/B evidence. T2 has been reverted to
     * 1024 to match the validated baseline — see tier_perf_target[]'s comment
     * in imperator_bpf.c for the full rationale. If T2 DVFS tuning is
     * revisited, update both this comment and the table in the same change. */
    u8 dsq_hint;
    u8 tick_counter;
    u8 __reserved[61];
} __attribute__((aligned(64)));

/* Statistics */
struct imperator_stats {
    u64 nr_new_flow_dispatches;
    u64 nr_old_flow_dispatches;
    u64 nr_tier_dispatches[CAKE_TIER_MAX];
    u64 nr_starvation_preempts_tier[CAKE_TIER_MAX];
    u64 nr_lock_holder_skips;
    u64 nr_irq_wake_boosts;
    u64 nr_waker_tier_boosts;
    /* C3: Burst credit accounting — informational, for TUI and graduation gate.
     *
     * nr_preempt_with_credit: incremented each time SCX_ENQ_PREEMPT credits
     *   burst_credit to a T1/T2 task.  Tracks how often preemption recovery
     *   fires, which is the expected mechanism for C3's jitter reduction.
     *
     * nr_burst_credit_consumed: incremented each time a task dispatches with
     *   non-zero burst_credit and extends its slice.  Ratio of consumed/credited
     *   shows whether earned credit is actually being used (tasks that earn credit
     *   but are re-preempted before consuming it will show a gap). */
    u64 nr_preempt_with_credit;
    u64 nr_burst_credit_consumed;

    /* C2-Infra: Dispatch latency telemetry aggregates — closes W4.
     *
     * jitter_ewma_us is per-task state in imperator_task_ctx and is not directly
     * accessible from the TUI without a BPF iterator.  Instead, imperator_running
     * accumulates two u64 aggregates here so the TUI can compute a system-wide
     * mean dispatch latency without new BPF infrastructure:
     *
     *   mean_jitter_us = nr_jitter_ewma_sum / nr_jitter_ewma_count
     *
     * nr_jitter_ewma_sum: sum of jitter_ewma_us samples (in ~µs units) added
     *   to each context switch where enqueue_time was non-zero (DSQ path only).
     *   Per-CPU; summed in aggregate_stats() in tui.rs.
     *
     * nr_jitter_ewma_count: number of samples added.  Always incremented in
     *   lockstep with nr_jitter_ewma_sum so the ratio is always valid.
     *
     * These fields overflow at ~18 × 10^18 samples (u64 max).  At 100K context
     * switches/sec this takes ~5.8 million years — not a practical concern. */
    u64 nr_jitter_ewma_sum;
    u64 nr_jitter_ewma_count;
    u64 _pad[15];
} __attribute__((aligned(64)));

/* Defaults (Gaming profile) */
#define CAKE_DEFAULT_QUANTUM_NS         (2 * 1000 * 1000)
#define CAKE_DEFAULT_NEW_FLOW_BONUS_NS  (8 * 1000 * 1000)
#define CAKE_DEFAULT_STARVATION_T0   3000000
#define CAKE_DEFAULT_STARVATION_T1   8000000
#define CAKE_DEFAULT_STARVATION_T2  40000000
/* FIX (desktop-policy/T3-starvation): tightened 100ms -> 50ms.
 *
 * CONTEXT: tier_perf_target[T3] was raised from 75% to 100% (see
 * tier_perf_target[]'s comment in imperator_bpf.c) under the desktop
 * philosophy that mains-powered systems should trade power for performance
 * rather than throttle background work for thermal headroom most desktops
 * don't need.
 *
 * PROBLEM THIS CLOSES: at 100% frequency a T3 task (shader compilation,
 * background compile, asset streaming) makes more forward progress per tick
 * than it did at 75% — including during a worst-case starvation run. A
 * previous revision's comment claimed starvation thresholds had been
 * tightened to compensate; they had not been (this constant was unchanged
 * at 100ms). That gap meant a foreground T0/T1/T2 task contending with an
 * unthrottled T3 task could wait the FULL unchanged 100ms ceiling — worse
 * than before, since the T3 task was now also doing more damage per ms of
 * that wait (full clock vs. 75%).
 *
 * FIX: halve the T3 ceiling to 50ms. This is still 1.25x T2's 40ms ceiling
 * (T3 retains meaningfully more rope than T2, consistent with "bulk work can
 * wait longer than frame-producing work") while bounding worst-case
 * foreground-thread wait to half of what an unthrottled-T3 system would
 * otherwise allow. Combined with the existing lock-holder skip and
 * O(1) bitmask preemption kick, this keeps the "more power, more throughput"
 * benefit on T3 while capping the worst case it can impose on T0-T2.
 *
 * This value has NOT been validated with the project's standard A/B
 * methodology (the Arc Raiders 1%-low test cited elsewhere in this file).
 * It is a reasoned default, not a measured optimum — treat it as a starting
 * point for that test, the same way any DVFS/starvation change should be
 * treated per the perf-regression-guard note on tier_perf_target[]. */
#define CAKE_DEFAULT_STARVATION_T3  50000000
#define CAKE_DEFAULT_MULTIPLIER_T0  512
#define CAKE_DEFAULT_MULTIPLIER_T1  1024
#define CAKE_DEFAULT_MULTIPLIER_T2  2048
#define CAKE_DEFAULT_MULTIPLIER_T3  4095
#define CAKE_DEFAULT_WAIT_BUDGET_T0 100000
#define CAKE_DEFAULT_WAIT_BUDGET_T1 2000000
#define CAKE_DEFAULT_WAIT_BUDGET_T2 8000000
#define CAKE_DEFAULT_WAIT_BUDGET_T3 0

/* Fused tier config: [Mult:12][Quantum:16][Budget:16][Starve:20] */
typedef u64 fused_config_t;

#define CFG_SHIFT_MULTIPLIER  0
#define CFG_SHIFT_QUANTUM     12
#define CFG_SHIFT_BUDGET      28
#define CFG_SHIFT_STARVATION  44

#define CFG_MASK_MULTIPLIER   0x0FFFULL
#define CFG_MASK_QUANTUM      0xFFFFULL
#define CFG_MASK_BUDGET       0xFFFFULL
#define CFG_MASK_STARVATION   0xFFFFFULL

#define UNPACK_MULTIPLIER(cfg)    ((cfg) & CFG_MASK_MULTIPLIER)
#define UNPACK_QUANTUM_NS(cfg)    ((((cfg) >> CFG_SHIFT_QUANTUM) & CFG_MASK_QUANTUM) << 10)
#define UNPACK_BUDGET_NS(cfg)     ((((cfg) >> CFG_SHIFT_BUDGET) & CFG_MASK_BUDGET) << 10)
#define UNPACK_STARVATION_NS(cfg) (((cfg) >> CFG_SHIFT_STARVATION) << 10)

#define PACK_CONFIG(q_kns, mult, budget_kns, starv_kns) \
    ((((u64)(mult) & CFG_MASK_MULTIPLIER) << CFG_SHIFT_MULTIPLIER) | \
     (((u64)(q_kns) & CFG_MASK_QUANTUM) << CFG_SHIFT_QUANTUM) | \
     (((u64)(budget_kns) & CFG_MASK_BUDGET) << CFG_SHIFT_BUDGET) | \
     (((u64)(starv_kns) & CFG_MASK_STARVATION) << CFG_SHIFT_STARVATION))

#define CAKE_FUTEX_OP_UNSET  0xFF

#endif /* __CAKE_INTF_H */
