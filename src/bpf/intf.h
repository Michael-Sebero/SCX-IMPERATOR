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

/* FLOW STATE FLAGS — packed_info bits [27:24] */
enum imperator_flow_flags {
    CAKE_FLOW_NEW         = 1 << 0,  /* DRR++ new-flow bonus still available */
    CAKE_FLAG_LOCK_HOLDER = 1 << 1,  /* returned from a futex wait/lock this run */
    CAKE_FLOW_IRQ_WAKE    = 1 << 2,  /* queued wakeup came from IRQ context */
};

/* EXTENDED FLAGS — packed_info bits [23:16] (Gen 6). One-shot, consumed by
 * the next enqueue/dispatch; written with atomic OR/AND like the flow flags. */
enum imperator_xflags {
    CAKE_XF_YIELDED    = 1 << 0,  /* sched_yield(): do not keep running in dispatch */
    CAKE_XF_LOCK_BOOST = 1 << 1,  /* preempted while holding a lock: deadline advance */
};
#define SHIFT_XFLAGS        16
#define XFLAG(f)            ((u32)(f) << SHIFT_XFLAGS)
#define FLOWFLAG(f)         ((u32)(f) << SHIFT_FLAGS)

/* Frame-cadence cap (Gen 6, from LAVD's wait_freq signal): a task whose
 * sleep-to-sleep period is at most this long, and that is idle for at least
 * 1/8 of each period, is held at T2 instead of T3. 34ms ≈ 29.4Hz, so any
 * thread paced at 30fps or faster qualifies. */
#define FRAME_CADENCE_MAX_US  34000

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
     * by alloc_task_ctx_cold.
     * FIELD NAME: kept as `overrun_count` to avoid disrupting external tools;
     *             the type (u8) and offset (byte 22) are unchanged.
     * STRUCT SIZE: the struct is exactly 64B; the _Static_assert below
     *   enforces this. */
    u8 overrun_count;

    /* lock_grace: slice extensions granted to a running lock holder this
     * run (0 or 1). Reset in imperator_stopping. */
    u8 lock_grace;

    /* pending_futex_op — tracepoint fallback op storage (lock.bpf.c).
     * Stores the futex op recorded at sys_enter_futex so sys_exit_futex can
     * act on it even if the task migrated CPUs while sleeping. Initialised
     * to CAKE_FUTEX_OP_UNSET (0xFF) because task storage is zero-filled and
     * 0 == FUTEX_WAIT would read as a successful wait. */
    u8 pending_futex_op;   /* byte 24 */
    u8 __align_pad[3];     /* bytes 25-27 */

    /* Dispatch-latency telemetry [Bytes 28-33]
     * enqueue_time: (u32)scx_bpf_now() at queued wakeup; consumed (zeroed)
     *   in imperator_running, which turns it into one latency sample.
     * jitter_ewma_us: α=1/8 EWMA of enqueue→running latency in ~µs (ns>>10). */
    u32 enqueue_time;      /* bytes 28-31 */
    u16 jitter_ewma_us;    /* bytes 32-33 */

    /* cadence_us: α=1/4 EWMA of the sleep-to-sleep period in ~µs (ns>>10),
     * saturating at 65535. 0 = no sample yet. Read by cadence_cap(). */
    u16 cadence_us;        /* bytes 34-35 */

    /* sleep_entry_time: (u32)scx_bpf_now() when the task last blocked.
     * Consumed by the post-sleep recovery check in imperator_enqueue. */
    u32 sleep_entry_time;  /* bytes 36-39 */

    /* burst_acc_us: CPU time (~µs, saturating) since the task last slept,
     * summed across preempted bouts and kept-running segments. */
    u16 burst_acc_us;      /* bytes 40-41 */
    u16 __pad16;           /* bytes 42-43 */

    /* last_sleep_at: (u32)scx_bpf_now() of the previous block; the delta to
     * the next block is one cadence sample. Not consumed. */
    u32 last_sleep_at;     /* bytes 44-47 */

    u8  __pad[16];         /* bytes 48-63: reserved */
} __attribute__((aligned(64)));

_Static_assert(sizeof(struct imperator_task_ctx) == 64,
    "imperator_task_ctx must be exactly 64B (one cache line) — update __pad if fields change");

/* packed_info bitfield layout:
 * [Stable:2][Tier:2][Flags:4][XFlags:8][Rsvd:16]
 *  31-30     29-28   27-24    23-16     15-0
 *
 * Bits [15:0] previously held WAIT_DATA [15:8] and KALMAN_ERROR [7:0].
 * Both were written (KALMAN_ERROR initialised to 0xFF in alloc_task_ctx_cold)
 * but never read by any scheduling decision in imperator_bpf.c, lock_bpf.c,
 * or the Rust side.  Removed per W2 audit finding.  Bits [23:0] are now
 * reserved (Rsvd) and must be zero except for future use. Gen 6 uses
 * bits [23:16] for the one-shot extended flags (enum imperator_xflags). */
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
    /* dsq_hint: DVFS perf-target hysteresis cache (u8, encodes cpuperf_target).
     * Name is historical (original use was DSQ selection hint, now removed);
     * the field stores the last written DVFS target to skip redundant kfunc
     * calls when the tier has not changed between ticks.
     *
     * Encoding (audit/F-02, supersedes the audit/Finding-2 encoding below):
     * stores ((cpuperf_target >> 3) + 1) as u8. cpuperf_target range is
     * [0, SCX_CPUPERF_ONE=1024], so the encoded range is [1, 129] — 0 is
     * reserved exclusively for "never written for this CPU" (the BSS-zero
     * default) and cannot be produced by any real target, including 1024:
     *   BSS zero          → dsq_hint=0  → always treated as unset, calls kfunc
     *   target=0            → dsq_hint=1
     *   target=768 (old T3) → dsq_hint=97
     *   target=1024 (max)   → dsq_hint=129
     *
     * The PREVIOUS encoding (>> 2, no offset) let target=1024 truncate to the
     * same u8 value as BSS-zero (1024>>2=256, which wraps to 0 in a u8) —
     * indistinguishable from "unset". Once tier_perf_target[] in
     * imperator_bpf.c was changed so every tier equals 1024 (desktop policy,
     * see that table's comment), every real target collided with the unset
     * sentinel and the hysteresis check was permanently "0 != 0" — false on
     * every tick, forever. scx_bpf_cpuperf_set() was never called on
     * non-hybrid systems. See DSQ_HINT_ENCODE/DSQ_HINT_UNSET in
     * imperator_bpf.c for the fix and full writeup; both call sites there
     * now also treat dsq_hint==0 as an explicit "unset, always call the
     * kfunc" case rather than relying on it comparing equal to a real target.
     *
     * NOTE (perf-regression-guard): an earlier revision of this comment
     * documented a planned T2 target of 896 (which under the old >>2 encoding
     * would have been dsq_hint=224) that was never applied to
     * tier_perf_target[] in imperator_bpf.c, and a later revision applied it
     * without supporting A/B evidence. T2 has been reverted to 1024 to match
     * the validated baseline — see tier_perf_target[]'s comment in
     * imperator_bpf.c for the full rationale. If T2 DVFS tuning is
     * revisited, update both this comment and the table in the same change. */
    u8 dsq_hint;
    u8 __rsvd8[2];
    /* lock_since (Gen 6): (u32)scx_bpf_now() at which the task now running
     * on this CPU returned from a futex wait/lock, 0 when it holds none.
     * Written only by the owning CPU (lock probes, imperator_stopping); read
     * by other CPUs choosing a preemption victim, which skip a CPU whose
     * lock was acquired less than lock_window_ns ago. */
    u32 lock_since;
    u8 __reserved[56];
} __attribute__((aligned(64)));
_Static_assert(sizeof(struct mega_mailbox_entry) == 64,
    "mega_mailbox_entry must be exactly 64B (one cache line)");

/* Statistics — per-CPU, summed by the loader (tui::aggregate_stats).
 * Exactly 32 u64 = 256B so global_stats[] entries stay 256B-aligned. */
struct imperator_stats {
    u64 nr_new_flow_dispatches;   /* wakeup dispatches (idle path + queued wakeups) */
    u64 nr_old_flow_dispatches;   /* re-queues: slice expiry, kicks, yields, new tasks */
    u64 nr_tier_dispatches[CAKE_TIER_MAX];
    /* nr_tick_preempts_tier: imperator_tick ended a task's slice because it
     * ran past next_slice while work was queued for its LLC (was
     * nr_starvation_preempts_tier, which could never fire). */
    u64 nr_tick_preempts_tier[CAKE_TIER_MAX];
    /* nr_lock_holder_protects: a running lock holder was spared — skipped as
     * a preemption victim, or kept running past its slice once. */
    u64 nr_lock_holder_protects;
    u64 nr_irq_wake_boosts;
    u64 nr_waker_tier_boosts;
    /* nr_preempt_kicks: T0/T1 enqueues that kicked a T3/T2 victim CPU. */
    u64 nr_preempt_kicks;
    /* mean dispatch latency = nr_jitter_ewma_sum / nr_jitter_ewma_count */
    u64 nr_jitter_ewma_sum;
    u64 nr_jitter_ewma_count;
    /* nr_prev_kept: ops.dispatch kept a task whose slice ended running
     * because its deadline was earlier than the head of its LLC queue. */
    u64 nr_prev_kept;
    /* nr_cadence_caps: full reclassifications where the frame-cadence cap
     * held a task at T2 that its burst length alone would have put in T3. */
    u64 nr_cadence_caps;
    u64 _pad[14];
} __attribute__((aligned(64)));
_Static_assert(sizeof(struct imperator_stats) == 256,
    "imperator_stats must be exactly 256B — update _pad if fields change");

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

/* FIX (audit/F-03): CAKE_DEFAULT_WAIT_BUDGET_T0-T3 removed, along with
 * CFG_SHIFT_BUDGET / CFG_MASK_BUDGET / UNPACK_BUDGET_NS below and the
 * budget_kns parameter of PACK_CONFIG. The values were fully computed
 * per-profile in main.rs's Profile::wait_budget() and packed into
 * tier_configs, but no BPF code path ever called UNPACK_BUDGET_NS —
 * confirmed by exhaustive grep across imperator_bpf.c and lock_bpf.c — and
 * no comment anywhere in the codebase documented what the field was meant
 * to drive. Rather than add new, unvalidated scheduling logic to make a
 * guessed-at purpose real, the field has been removed. Starvation has been
 * repacked from bit 44 down to bit 28 to reclaim the freed range instead of
 * leaving a gap; see the layout comment below. If a genuine wait-budget
 * mechanism is designed in the future, it should go through this project's
 * normal A/B validation (the Arc Raiders 1%-low methodology referenced
 * elsewhere in this file) before shipping, the same as any other tuning
 * change here. */

/* Fused tier config: [Mult:12][Quantum:16][Starve:20][Rsvd:16] */
typedef u64 fused_config_t;

#define CFG_SHIFT_MULTIPLIER  0
#define CFG_SHIFT_QUANTUM     12
#define CFG_SHIFT_STARVATION  28

#define CFG_MASK_MULTIPLIER   0x0FFFULL
#define CFG_MASK_QUANTUM      0xFFFFULL
#define CFG_MASK_STARVATION   0xFFFFFULL

#define UNPACK_MULTIPLIER(cfg)    ((cfg) & CFG_MASK_MULTIPLIER)
#define UNPACK_QUANTUM_NS(cfg)    ((((cfg) >> CFG_SHIFT_QUANTUM) & CFG_MASK_QUANTUM) << 10)
#define UNPACK_STARVATION_NS(cfg) (((cfg) >> CFG_SHIFT_STARVATION) << 10)

#define PACK_CONFIG(q_kns, mult, starv_kns) \
    ((((u64)(mult) & CFG_MASK_MULTIPLIER) << CFG_SHIFT_MULTIPLIER) | \
     (((u64)(q_kns) & CFG_MASK_QUANTUM) << CFG_SHIFT_QUANTUM) | \
     (((u64)(starv_kns) & CFG_MASK_STARVATION) << CFG_SHIFT_STARVATION))

#define CAKE_FUTEX_OP_UNSET  0xFF

#endif /* __CAKE_INTF_H */
