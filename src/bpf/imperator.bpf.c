// SPDX-License-Identifier: GPL-2.0
/* scx_imperator - CAKE DRR++ adapted for CPU scheduling: avg_runtime classification, direct dispatch, tiered DSQ */

#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include "intf.h"
#include "bpf_compat.h"

char _license[] SEC("license") = "GPL";

/* Scheduler RODATA config - JIT constant-folds these for ~200 cycle savings per decision */
const volatile u64 quantum_ns = CAKE_DEFAULT_QUANTUM_NS;
const volatile u64 new_flow_bonus_ns = CAKE_DEFAULT_NEW_FLOW_BONUS_NS;
const volatile bool enable_stats = false;

/* IRQ-wake boost on/off (--no-irq-boost clears it). */
const volatile bool irq_boost = true;

/* Topology config - JIT eliminates unused P/E-core steering when has_hybrid=false */
const volatile bool has_hybrid = false;

/* Gap-4 / Suggestion 1: P-core bitmask for hybrid placement steering.
 *
 * big_cpu_mask is a u64 bitmask where bit N=1 means CPU N is a Performance
 * core (P-core / big core).  Written by the Rust loader from topology.rs's
 * TopologyInfo::big_cpu_mask (which is derived from CoreType::Little detection
 * during sched_ext attachment).  Default 0 = all cores treated as equivalent
 * (non-hybrid or pre-loader state).
 *
 * Used in imperator_select_cpu to post-correct scx_bpf_select_cpu_dfl's idle
 * CPU selection: if the selected idle CPU is a little/E-core (bit not set in
 * big_cpu_mask), re-call scx_bpf_select_cpu_dfl with a P-core as the prev_cpu
 * hint to bias selection toward P-cores.  scx_bpf_select_cpu_dfl's internal
 * cascade (prev→sibling→LLC) means the hinted P-core is selected if idle.
 *
 * Implementation note: scx_bpf_pick_idle_cpu(cpumask*, flags) would be the
 * natural primitive, but it requires a struct cpumask* — building one at
 * runtime needs BPF arena allocation which imperator does not use.  The
 * double-call approach with a P-core hint reuses the existing idle-selection
 * infrastructure without new primitives.
 *
 * When has_hybrid=false: big_cpu_mask is never read (has_hybrid RODATA gate).
 * When big_cpu_mask=0 on a hybrid system: bit-test fails for all CPUs, the
 * early-out `!(big_cpu_mask & ...)` is false for cpu=0, but the BSF on 0
 * is guarded by `big_cpu_mask != 0` check — falls back cleanly. */
const volatile u64 big_cpu_mask = 0;


/* audit/G5-8: every global the loader writes through rodata must be
 * const volatile. A plain const global is an LLVM constant, so clang folds
 * reads to the initializer and the loader's value never reaches the code:
 * enable_stats=false compiled out all telemetry, nr_cpus=8 limited
 * llc_cpu_mask to CPUs 0-7, nr_llcs=1 and cpu_llc_id={} compiled out
 * per-LLC DSQs, and quantum_ns/new_flow_bonus_ns/has_hybrid and
 * constant-index tier_configs reads ignored the profile. */

/* Per-LLC DSQ partitioning — populated by loader from topology detection.
 * Eliminates cross-CCD lock contention: each LLC has its own DSQ.
 * Single-CCD (9800X3D): nr_llcs=1, identical to single-DSQ behavior.
 * Multi-CCD (9950X): nr_llcs=2, halves contention, eliminates cross-CCD atomics. */
const volatile u32 nr_llcs = 1;
const volatile u32 nr_cpus = 8;  /* Set by loader — bounds kick scan loop (Rule 39) */
const volatile u32 cpu_llc_id[CAKE_MAX_CPUS] = {};

/* SMT and core topology RODATA — populated by loader from topology.rs.
 *
 * These five fields complete the wiring from topology detection to BPF
 * scheduling decisions.  They were computed correctly in topology.rs and
 * received correctness fixes (threads_per_ccd max-reduce, cpu_thread_bit
 * SMT indexing) but were never written to BPF RODATA until now.
 *
 * cpu_core_id[cpu]:    Physical core ID for logical CPU `cpu`.  Used to
 *   look up core_cpu_mask[core_id] and core_thread_mask[core_id] from a
 *   logical CPU index.  Bridge between per-CPU and per-core arrays.
 *   Pattern matches cpu_llc_id: u32 array indexed by logical CPU ID.
 *
 * cpu_thread_bit[cpu]: Which SMT thread slot this logical CPU occupies
 *   within its physical core.  Value is a bitmask: 1 for the first thread,
 *   2 for the second (dual-SMT), etc.  Used in core occupancy checks:
 *   if (core_occupancy & cpu_thread_bit[cpu]) → this thread slot is busy.
 *
 * core_cpu_mask[core_id]: 64-bit bitmask of all logical CPUs that belong
 *   to physical core `core_id`.  Dual-SMT core: two bits set.  Used for
 *   fully-idle core detection: if both bits are idle the core has full
 *   resources available; a task placed there won't share with a sibling.
 *   Enables SMT-aware idle selection in hybrid steering.
 *
 * core_thread_mask[core_id]: Bitmask of all SMT slots in core `core_id`
 *   (e.g. 0x3 for dual-SMT).  A core is fully idle when none of its
 *   thread slots are occupied.  Used as the denominator in occupancy
 *   checks: fully_idle = (current_occupancy & core_thread_mask) == 0.
 *
 * threads_per_ccd: Number of logical CPUs (hardware threads) on the
 *   largest CCD.  CCD-fill threshold for work-stealing: if an LLC has
 *   fewer than threads_per_ccd tasks queued, the CCD is not saturated —
 *   work-stealing from it is premature and wastes cache.  Received the
 *   max-reduce fix (FIX #6) to handle asymmetric CCDs correctly.
 *
 * Default values (0/empty) are safe: callers guard with non-zero checks
 * or the has_hybrid RODATA gate eliminates the block entirely on non-hybrid
 * CPUs where these fields are not meaningful.
 *
 * FIX (Weakness-6): cpu_thread_bit[]/core_thread_mask[] are currently
 * dormant — still correctly wired from topology.rs, but with no reader.
 * The fully-idle-core check in imperator_select_cpu() that used to consume
 * them was simplified down to core_cpu_mask[] alone (see the comment there
 * for why); a real implementation of the "current_occupancy &
 * core_thread_mask" check described above would give these two arrays a
 * purpose again, but needs a live per-CPU occupancy signal this comment
 * isn't going to guess at — see that same comment for why. */
const volatile u32 cpu_core_id[CAKE_MAX_CPUS] = {};
const volatile u32 cpu_thread_bit[CAKE_MAX_CPUS] = {};
const volatile u64 core_cpu_mask[CAKE_MAX_CPUS] = {};
const volatile u32 core_thread_mask[CAKE_MAX_CPUS] = {};
const volatile u32 threads_per_ccd = 0;

/* [A] llc_cpu_mask — BSS, computed by imperator_init from cpu_llc_id RODATA.
 *
 * Writable at BPF runtime; guaranteed non-zero for any LLC with ≥1 CPU before
 * the first task is scheduled.  Eliminates the partial-deploy hazard where a
 * missing Rust-side write left the mask all-zeros and the O(1) bitmask kick
 * path silently produced zero kicks without any error or warning.
 *
 * LAYOUT: 8 × 8B = 64B, one cache line.  Read in imperator_enqueue: one miss
 * loads the entire array.  Read-only after imperator_init completes. */
u64 llc_cpu_mask[CAKE_MAX_LLCS] SEC(".bss") __attribute__((aligned(64)));

/* ═══════════════════════════════════════════════════════════════════════════
 * MEGA-MAILBOX: 64-byte per-CPU state (single cache line = optimal L1)
 * - Zero false sharing: each CPU writes ONLY to mega_mailbox[its_cpu]
 * - 50% less L1 pressure than 128B design (16 vs 32 cache lines)
 * ═══════════════════════════════════════════════════════════════════════════ */
struct mega_mailbox_entry mega_mailbox[CAKE_MAX_CPUS] SEC(".bss");

/* Per-LLC non-empty flag: one cache line per LLC, eliminating cross-LLC
 * coherence traffic on every enqueue.
 *
 * FIX (audit): The previous design used a single shared volatile u32
 * (llc_nonempty_mask) updated via __sync_fetch_and_or on every enqueue path.
 * On a 16-core dual-CCD system at ~100K enqueues/sec this forced the cache
 * line to bounce between all cores on every task placement — roughly 100ns of
 * unnecessary coherence traffic per enqueue (~1% overhead at peak).
 *
 * New design: each LLC writes ONLY its own entry.  Other LLCs read entries
 * they do not own only during the steal scan in imperator_dispatch, which is an
 * infrequent (drain) event.  Cross-LLC coherence traffic is eliminated on the
 * hot enqueue path and reduced to at most (nr_llcs - 1) reads on drain.
 *
 * Intra-LLC writes (multiple CPUs in the same LLC writing nonempty=1): still
 * share a cache line, but all CPUs write the same value (1), so the line
 * stays in Shared state on x86 MESIF — no false-sharing stall.
 *
 * Stale non-empty flags (set bit when DSQ has drained) are still harmless:
 * the dispatch steal path calls scx_bpf_dsq_move_to_local which returns 0
 * when empty, at which point we clear the flag. */
struct {
    u8 nonempty;
    u8 _pad[63];  /* Pad to one cache line — prevents false sharing between LLCs */
} __attribute__((aligned(64))) llc_nonempty[CAKE_MAX_LLCS] SEC(".bss")
    __attribute__((aligned(64)));

/* [B] tier_cpu_mask — per-tier bitmask of CPUs currently running tasks of that tier.
 *
 * INVARIANT: bit i of tier_cpu_mask[t] is set iff CPU i is currently running a
 * task whose EWMA tier is t.
 *
 * Responsibility split (no double-ownership):
 *   imperator_running  → sets   bit for the new task's tier  (never clears)
 *   imperator_stopping → clears bit for the stopping tier    (never sets)
 *                    MUST clear BEFORE reclassify_task_cold() so that
 *                    GET_TIER(tctx) still returns the running-time tier, not
 *                    the post-EWMA tier.
 *
 * CONCURRENCY: __sync_fetch_and_or / __sync_fetch_and_and map to BPF_ATOMIC_OR /
 * BPF_ATOMIC_AND (single instruction, not a CAS loop).  No two CPUs write the
 * same bit simultaneously (each CPU owns its own bit = 1ULL << cpu_id).
 *
 * LAYOUT: 4 × 8B = 32B.  All four tier words share one 64B cache line with
 * llc_cpu_mask when the allocator places them adjacently — both are loaded on
 * the T0/T1 kick path.  CAKE_TIER_MAX = 4 so the alignment covers the array. */
u64 tier_cpu_mask[CAKE_TIER_MAX] SEC(".bss") __attribute__((aligned(64)));

/* kick_pending_mask (Gen 6) — bit i set while CPU i has an outstanding T0/T1
 * preemption kick that it has not yet acted on.
 *
 * A kicker claims its victim with an atomic fetch-OR and only kicks when the
 * bit was clear, so concurrent T0/T1 wakeups pick distinct victims instead of
 * all landing on the lowest-numbered T3 CPU (LAVD gets the same effect by
 * CAS-ing the victim's est_stopping_clk in ask_cpu_yield_after()). The bit is
 * cleared by the victim itself in imperator_running (it switched tasks) or
 * imperator_tick (the kick did not lead to a switch).
 *
 * Own cache line: written only on kicks and by the victim, read on every
 * kick-eligible enqueue. */
u64 kick_pending_mask SEC(".bss") __attribute__((aligned(64)));
u8  __kick_pending_pad[56] SEC(".bss");

/* Helper: mark an LLC's DSQ as non-empty.  Skip the store when already set to
 * avoid a needless write to a hot cache line on every enqueue. */
static __always_inline void llc_mark_nonempty(u32 llc_id)
{
    u32 idx = llc_id & (CAKE_MAX_LLCS - 1);
    if (!imperator_relaxed_load_u8(&llc_nonempty[idx].nonempty))
        imperator_relaxed_store_u8(&llc_nonempty[idx].nonempty, 1);
}

/* Metadata accessors (Fused layout) */
#define GET_TIER_RAW(packed) EXTRACT_BITS_U32(packed, SHIFT_TIER, 2)
#define GET_TIER(ctx) GET_TIER_RAW(imperator_relaxed_load_u32(&(ctx)->packed_info))

/* Per-CPU scratch area - BSS-tunneled helper outputs, isolated to prevent MESI contention.
 *
 * FIX (audit): Removed dead fields bpf_iter_scx_dsq it and init_tier.
 * bpf_iter_scx_dsq was never referenced after the per-LLC DSQ migration;
 * init_tier is a local variable in alloc_task_ctx_cold, not a scratch field.
 * Together they consumed ~79B of the 128B line (4.8 KB across 64 CPUs) and
 * forced false-sharing through the iterator's alignment requirements. */
struct imperator_scratch {
    bool dummy_idle;            /* 1B: idle flag from scx_bpf_select_cpu_dfl */
    /* cached_llc/cached_now removed (audit/G5-1): ops.enqueue() also runs
     * without a preceding ops.select_cpu() on the same CPU, so the tunneled
     * values were stale on those paths. imperator_enqueue derives both. */
    u8   _pad[127];
} global_scratch[CAKE_MAX_CPUS] SEC(".bss") __attribute__((aligned(128)));
_Static_assert(sizeof(struct imperator_scratch) == 128,
    "imperator_scratch must be exactly 128B (2 cache lines) -- update _pad if fields change");

/* Global stats BSS array - 0ns lookup vs 25ns helper, 256-byte aligned per CPU */
struct imperator_stats global_stats[CAKE_MAX_CPUS] SEC(".bss") __attribute__((aligned(256)));

/* BSS tail guard - absorbs BTF truncation bugs instead of corrupting real data */
u8 __bss_tail_guard[64] SEC(".bss") __attribute__((aligned(64)));

/* LLC-pair ETD latency cost table — written from userspace after ETD calibration.
 * Unit: 4 ns/unit (0 = unknown or same LLC, 255 = ~1020 ns).
 * Zero-initialised (BSS): safe default before calibration completes — the steal
 * path treats all-zero costs as "no preference" and falls back to index order.
 *
 * Layout: llc_etd_cost[src_llc][dst_llc].  Values are symmetric (min round-trip
 * latency / 2) and set by the Rust-side try_write_etd_costs() after ETD finishes. */
u8 llc_etd_cost[CAKE_MAX_LLCS][CAKE_MAX_LLCS] SEC(".bss")
    __attribute__((aligned(64)));

/* Mailbox mask builders removed — select_cpu now delegates idle detection
 * to scx_bpf_select_cpu_dfl() which uses the kernel's authoritative idle
 * tracking (zero staleness, atomic claiming). */

static __always_inline struct imperator_stats *get_local_stats(void)
{
    u32 cpu = bpf_get_smp_processor_id();
    return &global_stats[cpu & (CAKE_MAX_CPUS - 1)];
}

/* ETD surgical seek / find_surgical_victim_logical removed — select_cpu
 * now delegates idle selection to scx_bpf_select_cpu_dfl() which does
 * prev → sibling → LLC cascade internally with kernel-native topology. */

/* Victim finder / arbiter removed — select_cpu now uses kernel-delegated
 * idle selection. When all CPUs are busy, enqueue handles placement via
 * per-LLC DSQs with vtime-encoded tier priority. */

/* User exit info for graceful scheduler exit */
UEI_DEFINE(uei);

/* Global vtime removed to prevent bus locking. Tasks inherit vtime from parent. */

/* Optimization: Precomputed threshold to avoid division in hot path */
/* BTF fix: Non-static + aligned(8) prevents tail truncation bug */
/* Cached threshold moved to RODATA */

/* A+B ARCHITECTURE: Per-LLC DSQs with vtime-encoded priority.
 * DSQ IDs: LLC_DSQ_BASE + 0, LLC_DSQ_BASE + 1, ... (one per LLC). */

/* FIX (W3): CAKE_DSQ_LC_BASE removed — defined as 1000 for per-CPU direct
 * dispatch queues but never referenced after the per-LLC DSQ migration.
 * Zero call sites confirmed by static analysis. */

/* Tier config table - 4 tiers + padding, AoS layout: single cache line fetch
 * FIX (audit/F-03): PACK_CONFIG's budget_kns argument removed — see intf.h
 * for the full rationale for removing the wait-budget field entirely. */
const volatile fused_config_t tier_configs[8] = {
    /* T0: Critical (<100µs) — IRQ, input, audio */
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T0,
                CAKE_DEFAULT_STARVATION_T0 >> 10),
    /* T1: Interactive (<2ms) — compositor, physics */
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T1,
                CAKE_DEFAULT_STARVATION_T1 >> 10),
    /* T2: Frame Producer (<8ms) — game render, encoding */
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T2,
                CAKE_DEFAULT_STARVATION_T2 >> 10),
    /* T3: Bulk (≥8ms) — compilation, background */
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T3,
                CAKE_DEFAULT_STARVATION_T3 >> 10),
    /* Padding (copies of T3 for safe & 7 access) */
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T3,
                CAKE_DEFAULT_STARVATION_T3 >> 10),
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T3,
                CAKE_DEFAULT_STARVATION_T3 >> 10),
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T3,
                CAKE_DEFAULT_STARVATION_T3 >> 10),
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T3,
                CAKE_DEFAULT_STARVATION_T3 >> 10),
};

/* audit/G5-3: LLC DSQ ordering is earliest-deadline-first with
 * deadline = enqueue time + the tier's starvation budget from tier_configs.
 *
 * The previous (tier << 56) | timestamp key was strict priority with no
 * aging: a queued T3 task waited behind every later T0-T2 arrival, and the
 * tick-side starvation check could not help it (it only inspects the running
 * task, and slice < threshold in every profile made it unreachable). Under
 * sustained T0-T2 saturation that ends in the sched_ext watchdog's
 * runnable-task-stall exit.
 *
 * Budgets increase with tier in every profile (and --starvation scales them
 * uniformly), so same-time arrivals keep strict tier order. A waiting task
 * overtakes newer higher-tier arrivals only after it has waited the budget
 * gap (Default: T1 6.5ms, T2 12ms, T3 80ms behind the next tier up). */
#ifndef barrier_var
#define barrier_var(var) asm volatile("" : "+r"(var))
#endif

static __always_inline u64 tier_deadline(u64 now, u8 tier, u64 advance)
{
    /* barrier_var() forces both index masks to be emitted. Without it clang
     * proves t - 1 <= 2 from the t > 0 test and drops the mask, while the
     * verifier tracks that test on a different register copy and rejects the
     * load ("R5 unbounded memory access"). */
    u32 t = tier;
    barrier_var(t);
    t = CAKE_TIER_IDX(t);
    u64 budget = UNPACK_STARVATION_NS(tier_configs[t]);

    if (advance && t > CAKE_TIER_CRITICAL) {
        u32 up = t - 1;
        barrier_var(up);
        up = CAKE_TIER_IDX(up);
        u64 above = UNPACK_STARVATION_NS(tier_configs[up]);
        u64 gap = budget > above ? budget - above - 1 : 0;
        if (advance > gap)
            advance = gap;
    }

    u64 dl = now + budget;
    return dl > advance ? dl - advance : 0;
}

/* Per-tier graduated backoff recheck masks (RODATA)
 * Lower tiers (more stable) recheck less often.
 * T0 IRQs almost never change behavior → every 1024th stop.
 * T3 bulk tasks may transition → every 16th stop. */
static const u16 tier_recheck_mask[] = {
    1023,  /* T0: every 1024th stop */
    127,   /* T1: every 128th  */
    31,    /* T2: every 32nd   */
    15,    /* T3: every 16th   */
    15, 15, 15, 15,  /* padding */
};

/* Vtime table removed - FIFO DSQs don't use dsq_vtime, saved 160B + 30 cycles */

/* Per-task context map */
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct imperator_task_ctx);
} task_ctx SEC(".maps");

/* Bitfield accessors - relaxed atomics prevent tearing */

/* Metadata Accessors - Definitions moved to top */

/* FIX (audit): Guard the shift arithmetic in alloc_task_ctx_cold that packs
 * both TIER and FLAGS bits in a single expression using SHIFT_FLAGS as the
 * base with +4 offset for tier.  If SHIFT_TIER or SHIFT_FLAGS are ever
 * changed independently, the expression silently misplaces one field. */
_Static_assert(SHIFT_TIER == SHIFT_FLAGS + 4,
    "alloc_task_ctx_cold init expression assumes SHIFT_TIER == SHIFT_FLAGS + 4 -- update packing");

/* COLD PATH: Task allocation + kthread init - noinline keeps I-Cache tight for hot path */
/* Removed accounting functions - now in tick */
/* set_victim_status_cold removed - mailbox handles victim status */

/* perform_lazy_accounting removed - accounting in tick */

/* init_new_kthread_cold inlined into imperator_enqueue — reuses hoisted
 * now_cached + enq_llc, saving 2 kfunc calls per kthread enqueue. */

/* select_cpu_new_task_cold removed — new tasks go through the same
 * scx_bpf_select_cpu_dfl path as all other tasks. */

static __attribute__((noinline))
struct imperator_task_ctx *alloc_task_ctx_cold(struct task_struct *p)
{
    struct imperator_task_ctx *ctx;

    /* Heavy allocator call */
    ctx = bpf_task_storage_get(&task_ctx, p, 0,
                               BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!ctx) return NULL;

    ctx->next_slice = quantum_ns;
    u16 init_deficit = (u16)((quantum_ns + new_flow_bonus_ns) >> 10);
    ctx->last_run_at = 0;
    ctx->reclass_counter = 0;
    ctx->overrun_count = 0;
    ctx->lock_grace = 0;

    /* Task storage is zero-filled on creation, so these stores are
     * redundant; they are kept so the init contract reads off this function
     * without knowing the storage guarantee. 0 is the "no sample / no stamp"
     * sentinel for every timestamp and EWMA below. */
    ctx->__align_pad[0] = 0;
    ctx->__align_pad[1] = 0;
    ctx->__align_pad[2] = 0;
    ctx->enqueue_time     = 0;
    ctx->jitter_ewma_us   = 0;
    ctx->cadence_us       = 0;
    ctx->sleep_entry_time = 0;
    ctx->burst_acc_us     = 0;
    ctx->__pad16          = 0;
    ctx->last_sleep_at    = 0;

    /* FIX (C-2): Initialise pending_futex_op to CAKE_FUTEX_OP_UNSET (0xFF).
     *
     * BPF task-storage zero-initialises new entries, giving pending_futex_op
     * the value 0 == CAKE_FUTEX_WAIT.  The guard in imperator_tp_exit_futex only
     * returns early when pending_futex_op == 0xFF (UNSET); with 0 it falls
     * through to the switch-case and calls set_lock_holder() for any
     * sys_exit_futex with ret==0 — including tasks whose first kernel event
     * is a successful futex return before any sys_enter_futex was observed.
     *
     * Writing 0xFF here makes the UNSET guard unconditionally safe: the field
     * stays 0xFF until imperator_tp_enter_futex records a real op, and the exit
     * handler skips cleanly until then. */
    ctx->pending_futex_op = CAKE_FUTEX_OP_UNSET;

    /* MULTI-SIGNAL INITIAL CLASSIFICATION
     *
     * Two cheap signals set the starting point; avg_runtime classification
     * takes over after the first few execution bouts and is authoritative.
     *
     * Signal 1: Nice value (u32 field read, ~2 cycles)
     *   - nice < 0 (prio < 120): OS/user explicitly prioritized
     *     System services (-20), pipewire (-11), games with nice (-5)
     *     → T0 initially, avg_runtime reclassifies after first runs
     *   - nice > 10 (prio > 130): explicitly deprioritized
     *     Background builds, indexers → T3, stays if bulk
     *   - nice 0-10: default → T1, avg_runtime adjusts naturally
     *
     * Signal 2: PF_KTHREAD flag (1 bit test, already known by caller)
     *   Kthreads with nice < 0 get T0 from Signal 1 automatically.
     *   Kthreads with nice 0 start at T1 like all other nice-0 tasks.
     *   No pin — reclassify based on actual avg_runtime behavior:
     *   - ksoftirqd: ~10μs bursts → T0 within 3 stops
     *   - kcompactd: long runs → T2-T3 naturally
     *
     * Signal 3: Runtime behavior (ongoing, ~15ns/stop — authoritative)
     *   Pure avg_runtime → tier mapping in reclassify_task_cold(). */

    /* Nice value: static_prio 100 = nice -20, 120 = nice 0, 139 = nice 19 */
    u32 prio = p->static_prio;
    u8 init_tier;

    if (prio < 120) {
        /* Negative nice: OS or user explicitly prioritized.
         * avg_runtime=0 at init → T0 until first reclassify. */
        init_tier = CAKE_TIER_CRITICAL;
    } else if (prio > 130) {
        /* High nice (>10): explicitly deprioritized.
         * Background builds, indexers, low-priority daemons. */
        init_tier = CAKE_TIER_BULK;
    } else {
        /* Default (nice 0-10): start at Interactive.
         * avg_runtime reclassifies to correct tier within ~3 stops. */
        init_tier = CAKE_TIER_INTERACT;
    }

    /* FIX (audit): Seed avg_runtime_us at the midpoint of the initial tier's
     * expected range rather than 0. Starting from 0 caused any task with a
     * short first execution bout (< tier gate / 16) to receive an EWMA of
     * rt/16 after one bout — fast enough to classify as T0 — regardless of
     * its long-term behavior.  A bulk task (nice >10) with a 200µs first
     * bout would earn T0 priority for 4–16 subsequent bouts before the EWMA
     * corrected, starving gaming threads at application startup time.
     *
     * Midpoints chosen as the geometric mean of adjacent gate values so the
     * EWMA converges to the correct tier within ~3 bouts for well-behaved tasks:
     *   T0 Critical  (< 100µs):   midpoint ≈  50µs
     *   T1 Interact  (< 2000µs):  midpoint ≈ 1050µs
     *   T2 Frame     (< 8000µs):  midpoint ≈ 5000µs
     *   T3 Bulk      (≥ 8000µs):  floor  = 8001µs */
    u16 init_avg_rt;
    if (init_tier == CAKE_TIER_CRITICAL)
        init_avg_rt = TIER_GATE_T0 / 2;
    else if (init_tier == CAKE_TIER_INTERACT)
        init_avg_rt = (TIER_GATE_T0 + TIER_GATE_T1) / 2;
    else if (init_tier == CAKE_TIER_FRAME)
        init_avg_rt = (TIER_GATE_T1 + TIER_GATE_T2) / 2;
    else
        init_avg_rt = TIER_GATE_T2 + 1;

    ctx->deficit_avg_fused = PACK_DEFICIT_AVG(init_deficit, init_avg_rt);

    u32 packed = 0;
    /* FIX (W2): Removed `packed |= (255 & MASK_KALMAN_ERROR) << SHIFT_KALMAN_ERROR`.
     * KALMAN_ERROR and WAIT_DATA were defined in intf.h and initialised here but
     * never read by any scheduling path.  The 255 init was a dead write that
     * occupied bits [7:0] of packed_info with a constant value.  Both defines
     * and this write are removed; bits [23:0] are now fully reserved (zero). */
    /* Fused TIER+FLAGS: bits [29:24] = [tier:2][flags:4] (Rule 37 coalescing) */
    packed |= (((u32)(init_tier & MASK_TIER) << 4) | (CAKE_FLOW_NEW & MASK_FLAGS)) << SHIFT_FLAGS;
    /* stable=0, rsvd=0: implicit from packed=0 */

    ctx->packed_info = packed;

    return ctx;
}

/* Get/init task context - hot path: fast lookup only, cold path: noinline alloc */
static __always_inline struct imperator_task_ctx *get_task_ctx(struct task_struct *p, bool create)
{
    struct imperator_task_ctx *ctx;

    /* Fast path: lookup existing context */
    ctx = bpf_task_storage_get(&task_ctx, p, 0, 0);
    if (ctx)
        return ctx;

    /* If caller doesn't want allocation, return NULL */
    if (!create)
        return NULL;

    /* Slow path: delegate to cold section */
    return alloc_task_ctx_cold(p);
}

/* Noinline accounting - math-heavy ops moved here to free registers (now fully async in tick) */

/* T0 victim cold path removed — when all CPUs are busy, tasks go through
 * enqueue → per-LLC DSQ where vtime ordering ensures T0 tasks get pulled
 * first. Preemption is the T0/T1 victim kick in imperator_enqueue plus the
 * slice check in imperator_tick. */

/* ═══════════════════════════════════════════════════════════════════════════
 * KERNEL-FIRST FLAT SELECT_CPU: ~20 instructions vs ~200+ in the old cascade.
 *
 * Architecture: delegate idle detection to the kernel's authoritative
 * scx_bpf_select_cpu_dfl() which does prev → sibling → LLC cascade internally
 * with zero staleness and atomic claiming. When all CPUs are busy, return
 * prev_cpu and let imperator_enqueue handle via per-LLC DSQ with vtime ordering.
 *
 * Benefits (tier-agnostic by design — all tiers equally important):
 * - All tiers 0-3 take the same placement path (tiers define latency, not affinity)
 * - Zero bpf_task_storage_get in select_cpu (no tier/slice needed)
 * - Zero mailbox reads (kernel has authoritative idle data)
 * - Zero stale mask cascades (kernel idle bitmap is real-time)
 * - ~90-110 cycles vs ~200-500 cycles (~20-40ns p50 improvement)
 * ═══════════════════════════════════════════════════════════════════════════ */
/* ── IRQ-SOURCE WAKEUP DETECTION (adapted from LAVD lavd_select_cpu) ──────
 * True when this wakeup is being issued from hardirq/NMI/softirq context or
 * by ksoftirqd. ops.select_cpu() runs in the waker's context, so this is the
 * only callback where the interrupt context is still observable. Off with
 * --no-irq-boost (irq_boost = false), which the verifier folds away.
 *
 * Gen 6: the preempt-count helpers in bpf_compat.h replace the __weak
 * bpf_in_* kfunc declarations, which never resolved (see there). */
static __always_inline bool wakeup_from_irq(u64 wake_flags)
{
    if (!irq_boost)
        return false;

    if (imperator_in_hardirq_or_nmi() || imperator_in_serving_softirq())
        return true;

    /* ksoftirqd runs deferred softirq work in task context. A SYNC wakeup
     * is never issued from it, so skip the comm compare for those. */
    if (!(wake_flags & SCX_WAKE_SYNC)) {
        struct task_struct *waker = bpf_get_current_task_btf();
        if (waker && (waker->flags & PF_KTHREAD) &&
            __builtin_memcmp(waker->comm, "ksoftirqd/", 10) == 0)
            return true;
    }
    return false;
}

s32 BPF_STRUCT_OPS(imperator_select_cpu, struct task_struct *p, s32 prev_cpu,
                   u64 wake_flags)
{
    /* audit/G5-5: SCX_WAKE_SYNC is left to scx_bpf_select_cpu_dfl(). It
     * prefers an idle cache-affine prev_cpu, and only co-locates the wakee
     * with the waker when the waker's local DSQ is empty and idle CPUs
     * exist. */
    u32 tc_id = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
    struct imperator_scratch *scr = &global_scratch[tc_id];
    s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &scr->dummy_idle);

    if (scr->dummy_idle) {
        /* Direct dispatch onto the idle CPU with the task's own slice.
         *
         * Gen 6: the IRQ-wake flag is no longer stamped (and then consumed)
         * on this path. The task runs immediately, so a boost has nothing to
         * reorder; the only effect it used to have here was cutting the slice
         * to the T0 slice, e.g. a T2 render thread woken by a GPU-fence IRQ
         * got 0.5ms instead of its 4ms and was re-queued mid-frame whenever
         * anything else was waiting in the LLC. */
        struct imperator_task_ctx *tctx = bpf_task_storage_get(&task_ctx, p, 0, 0);
        u64 slice = tctx ? tctx->next_slice : quantum_ns;
        u8  tier  = tctx ? CAKE_TIER_IDX(GET_TIER(tctx)) : CAKE_TIER_INTERACT;

        /* Gap-4 / Suggestion 1: Hybrid P/E-core placement steering — SMT-aware.
         *
         * PROBLEM: scx_bpf_select_cpu_dfl selects any idle CPU without regard
         * for core type.  On Intel hybrid (P/E-core) or ARM big.LITTLE systems,
         * a T0 audio callback or T2 render thread may land on an E-core and stay
         * there — DVFS cannot compensate for lower E-core IPC.
         *
         * FIX (two-pass, SMT-aware):
         *
         * Pass 1 — Fully-idle P-core preference:
         *   Scan big_cpu_mask for P-cores whose ENTIRE physical core is idle
         *   (both SMT threads free: core_cpu_mask bits not occupied by any
         *   running task).  A fully-idle P-core gives the task full IPC and
         *   cache resources without sharing with a concurrently-running sibling.
         *   This is the highest-quality placement on a hybrid system.
         *
         * Pass 2 — Half-idle P-core fallback:
         *   If no fully-idle P-core is available (common on loaded systems),
         *   accept any P-core with at least one idle SMT thread slot — same
         *   approach as the original single-pass scan but now explicitly
         *   preferred over a fully-idle E-core.
         *
         * If neither pass finds an acceptable P-core, the original E-core
         * selection from scx_bpf_select_cpu_dfl stands unchanged.
         *
         * Implementation: BSF + clear-LSB iteration over big_cpu_mask bits.
         * For each candidate P-core CPU:
         *   - Check task affinity (bpf_cpumask_test_cpu on p->cpus_ptr)
         *   - Check full-core idle: core_cpu_mask[core_id] has no other
         *     thread bits set beyond this CPU's own thread slot.
         * Then re-call scx_bpf_select_cpu_dfl with the best candidate as
         * prev_cpu hint — the kernel's idle-claiming cascade atomically
         * claims the CPU if still idle.
         *
         * When has_hybrid=false: entire block is RODATA-gated (JIT folds).
         * When P-core already selected: 1 bit-test, exits immediately.
         * Pass 1 cost (fully-idle found): ~30-50 cycles, idle path only.
         * Pass 2 cost (half-idle fallback): same, plus one extra scan pass.
         * No-P-core cost: full scan + falls through unchanged. */
        if (has_hybrid && big_cpu_mask != 0 &&
            !(big_cpu_mask & (1ULL << ((u32)cpu & 63)))) {

            s32 best_full = -1;   /* best fully-idle P-core CPU */
            s32 best_half = -1;   /* best half-idle P-core CPU (fallback) */

            u64 candidate_mask = big_cpu_mask;
            for (int i = 0; i < CAKE_MAX_CPUS && candidate_mask; i++) {
                u32 pcpu = BIT_SCAN_FORWARD_U64(candidate_mask);
                candidate_mask &= candidate_mask - 1;

                if (!bpf_cpumask_test_cpu(pcpu, p->cpus_ptr))
                    continue;  /* task affinity excludes this P-core */

                /* Check whether the full physical core is idle.
                 * core_id is u32; guard against array bounds. */
                u32 core_id = cpu_core_id[pcpu & (CAKE_MAX_CPUS - 1)];
                if (core_id < CAKE_MAX_CPUS && core_cpu_mask[core_id] != 0) {
                    /* Fully-idle-core check.
                     *
                     * FIX (Weakness-6): this used to OR together three
                     * clauses. Simulated topology.rs's exact population
                     * logic for core_cpu_mask/core_thread_mask/cpu_thread_bit
                     * across single-thread cores, dual-SMT with both adjacent
                     * and non-adjacent sibling numbering (AMD-style
                     * interleaving), 4-way SMT, and 2000+ randomized layouts:
                     * clauses 2 and 3 never differed from clause 1 alone in
                     * any of them. That's not a coincidence, it follows from
                     * how topology.rs populates these arrays — is_big is
                     * computed once per physical core and applied uniformly
                     * to every logical CPU in that core, so whenever the
                     * whole core is a P-core, a sibling present in
                     * core_cpu_mask[core_id] is *always* also present in
                     * big_cpu_mask (clause 2 can never fire), and
                     * core_thread_mask[core_id]/cpu_thread_bit[pcpu] encode
                     * the identical "how many threads does this core have"
                     * fact as core_cpu_mask, just via a different bit layout
                     * (clause 3 can never disagree with clause 1). Reduced to
                     * the one clause that actually carries information:
                     *
                     * sibling_bits == 0: no other logical CPU shares this
                     * physical core with pcpu — single-thread core, or no
                     * sibling is registered — so pcpu gets the whole
                     * physical core to itself.
                     *
                     * This equivalence rests on topology.rs's per-core
                     * uniform is_big assignment staying true (see the
                     * core_id_usize loop in topology.rs::detect()). If that
                     * loop is ever changed to assign is_big per-thread rather
                     * than per-core, this comment goes stale the same way
                     * the old "waker_tier + 1" one did — worth a second look
                     * here if topology.rs's P/E-core detection changes.
                     *
                     * Separately: core_thread_mask[]/cpu_thread_bit[] are now
                     * unused by this function. Their RODATA doc comment above
                     * (search "current_occupancy") describes a genuinely
                     * different, more useful check they were meant to
                     * support — whether a sibling thread is *currently
                     * running something*, not just whether one exists —
                     * which the old clause 3 never actually computed despite
                     * the name. That's a real gap between documented intent
                     * and what shipped. Closing it needs a live per-CPU
                     * occupancy signal (e.g. __COMPAT_scx_bpf_cpu_curr() on the sibling;
                     * scx_bpf_cpu_rq() is deprecated),
                     * and I don't have enough confidence in the exact struct
                     * rq field access across kernel versions to write that
                     * here without source in hand to check it against — same
                     * reasoning as the FUTEX_CMP_REQUEUE_PI gap in
                     * lock_bpf.c. Left for a follow-up, not guessed at. */
                    u64 cmask = core_cpu_mask[core_id];
                    u64 sibling_bits = cmask & ~(1ULL << pcpu);
                    bool full_idle = (sibling_bits == 0);
                    if (full_idle && best_full < 0)
                        best_full = (s32)pcpu;
                    else if (best_half < 0)
                        best_half = (s32)pcpu;
                } else {
                    /* No core mask data (single-thread core or non-SMT):
                     * treat as half-idle candidate. */
                    if (best_half < 0)
                        best_half = (s32)pcpu;
                }

                /* Short-circuit: found a fully-idle P-core — no need to scan further */
                if (best_full >= 0)
                    break;
            }

            s32 pcpu_hint = (best_full >= 0) ? best_full : best_half;

            if (pcpu_hint >= 0) {
                bool dummy_idle2 = false;
                s32 pcpu_result = scx_bpf_select_cpu_dfl(p, pcpu_hint,
                                                          wake_flags,
                                                          &dummy_idle2);
                if (dummy_idle2)
                    cpu = pcpu_result;
                /* else: P-core became busy — keep original E-core selection */
            }
        }

        /* audit/G5-5: wake_flags are SCX_WAKE_* bits, not SCX_ENQ_* bits.
         * On 6.12-6.18 WF_SYNC (0x10) equals ENQUEUE_HEAD (0x10), so SYNC
         * wakees were inserted at the head of the local DSQ. */
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, slice, 0);

        /* FIX (#11): Count idle-path direct dispatches for accurate TUI stats. */
        if (enable_stats) {
            struct imperator_stats *s = get_local_stats();
            if (s) {
                s->nr_new_flow_dispatches++;
                if (tier < CAKE_TIER_MAX)
                    s->nr_tier_dispatches[tier]++;
            }
        }

        return cpu;
    }

    /* ALL BUSY: imperator_enqueue queues the task in the LLC DSQ of
     * task_cpu(p) (== prev_cpu here). Tag interrupt-sourced wakeups so that
     * enqueue can boost them; the task storage lookup is paid only here. */
    if (unlikely(wakeup_from_irq(wake_flags))) {
        struct imperator_task_ctx *irq_tctx = bpf_task_storage_get(&task_ctx, p, 0, 0);
        if (irq_tctx)
            __sync_fetch_and_or(&irq_tctx->packed_info,
                                FLOWFLAG(CAKE_FLOW_IRQ_WAKE));
    }

    return prev_cpu;
}

/* Lock-holder protection window (Gen 6): a CPU whose running task returned
 * from a futex wait/lock less than this long ago is not chosen as a
 * preemption victim, and the task may be kept running once past its slice.
 * Bounded on purpose: futex_wait() returning 0 also marks condvar and
 * job-queue waiters, so the protection must not cover a whole long run.
 * Scales with the profile's quantum (Default 0.5ms, Esports 0.25ms, Sim 1ms). */
#define LOCK_WINDOW_NS  (quantum_ns >> 2)

static __always_inline bool lock_window_open(u32 since, u32 now32)
{
    return since && (u64)(u32)(now32 - since) < LOCK_WINDOW_NS;
}

/* Slice for a task re-entering the queue without a wakeup (slice expiry,
 * kick, yield, new task) or kept running by dispatch: one base quantum,
 * never more than the tier's own slice (a T0 task used to get 4x its 0.5ms
 * slice here). */
static __always_inline u64 requeue_slice(struct imperator_task_ctx *tctx)
{
    u64 s = tctx ? tctx->next_slice : quantum_ns;
    return s < quantum_ns ? s : quantum_ns;
}

/* ── PREEMPTION VICTIM CLAIM (Gen 6, adapted from LAVD preempt.bpf.c) ─────
 * Walk up to 8 candidate CPUs (lowest index first) and claim the first one
 * that (a) the task may run on, (b) is not running a lock holder inside its
 * protection window, and (c) no other enqueue has already claimed.
 *
 * Up to Gen 5 the victim was simply the lowest-numbered T3 (else T2) CPU in
 * the LLC: a burst of T0/T1 wakeups kicked the same CPU over and over, and a
 * task pinned or affinitized elsewhere (per-CPU kworkers, Wine threads with
 * an affinity mask) kicked a CPU it could not run on, so the kick was wasted
 * and the task still waited. */
static __always_inline s32 claim_victim(struct task_struct *p, u64 cand, u32 now32)
{
    for (int i = 0; i < 8 && cand; i++) {
        u32 cpu = BIT_SCAN_FORWARD_U64(cand);
        cand &= cand - 1;
        /* Keep the mask in the bytecode: the verifier must see cpu < 64
         * before the mailbox index below (CTZ lowers to a table lookup). */
        barrier_var(cpu);
        cpu &= CAKE_MAX_CPUS - 1;

        if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
            continue;

        u32 since = imperator_relaxed_load_u32(&mega_mailbox[cpu].lock_since);
        if (unlikely(lock_window_open(since, now32))) {
            if (enable_stats) {
                struct imperator_stats *s = get_local_stats();
                if (s) s->nr_lock_holder_protects++;
            }
            continue;
        }

        u64 bit = 1ULL << cpu;
        if (__sync_fetch_and_or(&kick_pending_mask, bit) & bit)
            continue;  /* another enqueue claimed it first */
        return (s32)cpu;
    }
    return -1;
}

/* ── [F] PREEMPTION KICK ──────────────────────────────────────────────────
 * A T0/T1 task was queued while every CPU was busy: kick a CPU in the same
 * LLC that runs lower-priority work — T3 first, T2 only when no T3 CPU is
 * eligible — so it reschedules and pulls the waiting task from the LLC DSQ.
 * T0/T1 CPUs are never victims, and T2/T3 enqueues never kick (A/B: kicking
 * for T3 cost 16fps of 1% lows in Arc Raiders).
 *
 * Candidates come from tier_cpu_mask[t] & llc_cpu_mask[llc]: O(1) masks
 * maintained by imperator_running/imperator_stopping. CPUs with a kick still
 * pending are filtered up front; claim_victim() re-checks atomically. */
static __always_inline void try_preempt_victim(struct task_struct *p, u32 llc, u64 now)
{
    u64 llc_mask = imperator_relaxed_load_u64(&llc_cpu_mask[llc & (CAKE_MAX_LLCS - 1)]);
    u64 pending  = imperator_relaxed_load_u64(&kick_pending_mask);
    u64 allowed  = ~0ULL;

    /* A single-CPU task can only ever be helped by its own CPU. */
    if (p->nr_cpus_allowed == 1)
        allowed = 1ULL << ((u32)scx_bpf_task_cpu(p) & (CAKE_MAX_CPUS - 1));

    u64 base = llc_mask & allowed & ~pending;
    if (!base)
        return;

    s32 victim = claim_victim(p,
        imperator_relaxed_load_u64(&tier_cpu_mask[CAKE_TIER_BULK]) & base, (u32)now);
    if (victim < 0)
        victim = claim_victim(p,
            imperator_relaxed_load_u64(&tier_cpu_mask[CAKE_TIER_FRAME]) & base, (u32)now);
    if (victim < 0)
        return;

    scx_bpf_kick_cpu(victim, SCX_KICK_PREEMPT);
    if (enable_stats) {
        struct imperator_stats *s = get_local_stats();
        if (s) s->nr_preempt_kicks++;
    }
}

/* Enqueue - A+B architecture: per-LLC DSQ ordered by tier deadline (tier_deadline()) */
void BPF_STRUCT_OPS(imperator_enqueue, struct task_struct *p, u64 enq_flags)
{
    register struct task_struct *p_reg asm("r6") = p;
    u32 task_flags = p_reg->flags;

    /* audit/G5-1: ops.enqueue() is reached without a same-CPU ops.select_cpu()
     * on slice expiry, kicks, sched_yield, property changes, and wakeups of
     * tasks with nr_cpus_allowed == 1 (and, before 6.15, cross-LLC wakeups
     * delivered through the ttwu wakelist), so derive time and LLC here. */
    u32 enq_cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
    u64 now_cached = scx_bpf_now();
    u32 enq_llc = cpu_llc_id[(u32)scx_bpf_task_cpu(p_reg) & (CAKE_MAX_CPUS - 1)] &
                  (CAKE_MAX_LLCS - 1);

    struct imperator_task_ctx *tctx = get_task_ctx(p_reg, false);

    /* FIX (#10): kthreads seen before imperator_enable allocated their
     * context are queued at T1 (the nice-0 seed), not T0. */
    if (unlikely((task_flags & PF_KTHREAD) && !tctx)) {
        u64 vtime = tier_deadline(now_cached, CAKE_TIER_INTERACT, 0);
        scx_bpf_dsq_insert_vtime(p_reg, LLC_DSQ_BASE + enq_llc, quantum_ns, vtime, enq_flags);
        llc_mark_nonempty(enq_llc);
        return;
    }

    register struct imperator_task_ctx *tctx_reg asm("r7") = tctx;

    /* ── RE-QUEUE PATH: slice expiry, preemption kick, yield, new task ──────
     * FIX (#3): queued at the task's own tier (T3 only without a context),
     * with a fresh deadline: a task that was running goes behind same-tier
     * work that queued before it.
     *
     * Gen 6: a task switched out while holding a futex-acquired lock
     * (CAKE_XF_LOCK_BOOST, set in imperator_stopping) gets the within-tier
     * lock advance once, so it gets back on a CPU and releases the lock
     * sooner. The inactive C3 burst credit that used to sit here (it keyed
     * on an SCX_ENQ_PREEMPT flag ops.enqueue() never receives) is removed. */
    if (!(enq_flags & (SCX_ENQ_WAKEUP | SCX_ENQ_PREEMPT))) {
        u8  rq_tier = CAKE_TIER_BULK;
        u64 advance = 0;

        if (tctx_reg) {
            rq_tier = CAKE_TIER_IDX(GET_TIER(tctx_reg));
            u32 rq_packed = imperator_relaxed_load_u32(&tctx_reg->packed_info);
            if (unlikely(rq_packed & XFLAG(CAKE_XF_LOCK_BOOST))) {
                __sync_fetch_and_and(&tctx_reg->packed_info, ~XFLAG(CAKE_XF_LOCK_BOOST));
                advance = new_flow_bonus_ns;
            }
        }

        u64 vtime = tier_deadline(now_cached, rq_tier, advance);

        if (enable_stats) {
            struct imperator_stats *s = get_local_stats();
            if (s) {
                s->nr_old_flow_dispatches++;
                s->nr_tier_dispatches[rq_tier & (CAKE_TIER_MAX - 1)]++;
            }
        }

        scx_bpf_dsq_insert_vtime(p_reg, LLC_DSQ_BASE + enq_llc,
                                 requeue_slice(tctx_reg), vtime, enq_flags);
        llc_mark_nonempty(enq_llc);
        return;
    }

    if (unlikely(!tctx_reg)) {
        /* No context yet - use Frame tier */
        u64 vtime = tier_deadline(now_cached, CAKE_TIER_FRAME, 0);
        scx_bpf_dsq_insert_vtime(p_reg, LLC_DSQ_BASE + enq_llc, quantum_ns, vtime, enq_flags);
        llc_mark_nonempty(enq_llc);
        return;
    }

    /* C2-Infra: stamp the queue-entry time for dispatch-latency telemetry;
     * imperator_running turns it into one sample and zeroes it. */
    tctx_reg->enqueue_time = (u32)now_cached;

    /* FIX (audit/F-01): post-sleep recovery. sleep_entry_time is stamped in
     * imperator_stopping when the task blocks and consumed here at its next
     * queued wakeup. After a sleep longer than 500ms, move avg_runtime
     * halfway to the midpoint of the current tier so a thread that spent a
     * loading screen in T3 does not need 10+ bursts to recover. Both values
     * are u32 truncations of scx_bpf_now(), so sleeps over ~4.3s wrap and
     * may not trigger; recovery then falls back to normal EWMA convergence. */
    if (tctx_reg->sleep_entry_time != 0) {
        u32 sleep_ns = (u32)now_cached - tctx_reg->sleep_entry_time;
        if (sleep_ns > 500000000U) {
            static const u16 tier_sleep_mid[4] = { 50, 1050, 5000, 8001 };
            u8  s_tier    = GET_TIER(tctx_reg);
            u32 cur_fused = tctx_reg->deficit_avg_fused;
            u16 cur_avg   = EXTRACT_AVG_RT(cur_fused);
            u16 mid       = tier_sleep_mid[CAKE_TIER_IDX(s_tier) & 3];
            tctx_reg->deficit_avg_fused = PACK_DEFICIT_AVG(EXTRACT_DEFICIT(cur_fused),
                                                            (u16)((cur_avg + mid) >> 1));
        }
        tctx_reg->sleep_entry_time = 0;  /* one-shot per genuine sleep */
    }

    /* Standard Tier Logic */
    u8  own_tier = CAKE_TIER_IDX(GET_TIER(tctx_reg));
    u8  tier = own_tier;
    u64 slice = tctx_reg->next_slice;

    /* Load packed_info once — shared by the feature checks below. */
    u32 task_packed = imperator_relaxed_load_u32(&tctx_reg->packed_info);

    /* ── FEATURE 1: IRQ-SOURCE TIER OVERRIDE (adapted from LAVD) ──────────
     * imperator_select_cpu stamped CAKE_FLOW_IRQ_WAKE: the task was woken
     * from hardirq/softirq context (input, audio DMA, GPU fence, network,
     * and on non-RT kernels every hrtimer sleep). One-shot; the EWMA tier is
     * untouched and the slice stays the task's own.
     *
     * Gen 6: a T3 task is lifted to T2, not T0. LAVD treats an IRQ wakeup as
     * a weight on latency criticality, so a long-burst task gains little from
     * it; here a bulk task woken by a disk-completion or timer IRQ used to
     * sort ahead of every waiting render thread and kick a T2 CPU. At T2 it
     * still goes ahead of other bulk work, but it can no longer preempt. */
    if (unlikely(task_packed & FLOWFLAG(CAKE_FLOW_IRQ_WAKE))) {
        __sync_fetch_and_and(&tctx_reg->packed_info, ~FLOWFLAG(CAKE_FLOW_IRQ_WAKE));
        task_packed &= ~FLOWFLAG(CAKE_FLOW_IRQ_WAKE);
        tier = (own_tier == CAKE_TIER_BULK) ? CAKE_TIER_FRAME : CAKE_TIER_CRITICAL;

        if (enable_stats) {
            struct imperator_stats *s = get_local_stats();
            if (s) s->nr_irq_wake_boosts++;
        }
    }

    /* ── FEATURE 2: WAKER TIER INHERITANCE (adapted from LAVD) ─────────────
     * When a higher-priority task wakes this one, promote it to the waker's
     * tier for this dispatch, floored at T1 (genuine T0 comes only from the
     * task's own history or an IRQ wakeup). The waker's tier is read from
     * the per-CPU mailbox that imperator_running writes; MBOX_VALID_FLAG
     * tells a T0 waker (0x80) apart from a never-written mailbox (0x00).
     *
     * On 6.15+ ops.enqueue() for a wakeup runs on the waker's CPU; on
     * 6.12-6.14 wakelist-delivered wakeups read the target CPU's mailbox.
     *
     * Gen 6: a T3 wakee is lifted to T2 at most. LAVD caps inherited
     * criticality at 25% of the wakee's own so the task's own behaviour stays
     * dominant; the IMPERATOR equivalent is that bulk work never inherits a
     * kick-eligible tier. */
    if ((enq_flags & SCX_ENQ_WAKEUP) && tier > CAKE_TIER_CRITICAL) {
        struct mega_mailbox_entry *waker_mbox = &mega_mailbox[enq_cpu];
        u8 cur_mbox_flags = imperator_relaxed_load_u8(&waker_mbox->flags);
        if (cur_mbox_flags & MBOX_VALID_FLAG) {
            u8 waker_tier = MBOX_GET_TIER(cur_mbox_flags);
            u8 promoted = (waker_tier < CAKE_TIER_INTERACT) ? CAKE_TIER_INTERACT
                                                             : waker_tier;
            if (own_tier == CAKE_TIER_BULK && promoted < CAKE_TIER_FRAME)
                promoted = CAKE_TIER_FRAME;
            if (promoted < tier) {
                tier = promoted;
                if (enable_stats) {
                    struct imperator_stats *s = get_local_stats();
                    if (s) s->nr_waker_tier_boosts++;
                }
            }
        }
    }

    if (enable_stats) {
        struct imperator_stats *s = get_local_stats();
        if (s) {
            s->nr_new_flow_dispatches++;
            s->nr_tier_dispatches[tier & (CAKE_TIER_MAX - 1)]++;
        }
    }

    /* ── DEADLINE ADVANCES (DRR++ new flow, lock boost) ─────────────────────
     * CAKE_FLOW_NEW: a task still inside its initial deficit sorts ahead of
     * established same-tier tasks (cleared by reclassify_task_cold when the
     * deficit runs out). CAKE_XF_LOCK_BOOST: one-shot advance for a task
     * that was preempted while holding a lock. tier_deadline() caps the sum
     * below the gap to the next tier's budget, so an advance only reorders a
     * task within its own tier. */
    u64 advance = 0;
    if (task_packed & FLOWFLAG(CAKE_FLOW_NEW))
        advance += new_flow_bonus_ns;
    if (unlikely(task_packed & XFLAG(CAKE_XF_LOCK_BOOST))) {
        __sync_fetch_and_and(&tctx_reg->packed_info, ~XFLAG(CAKE_XF_LOCK_BOOST));
        advance += new_flow_bonus_ns;
    }

    u64 vtime = tier_deadline(now_cached, tier, advance);

    scx_bpf_dsq_insert_vtime(p_reg, LLC_DSQ_BASE + enq_llc, slice, vtime, enq_flags);
    llc_mark_nonempty(enq_llc);

    if (tier <= CAKE_TIER_INTERACT)
        try_preempt_victim(p_reg, enq_llc, now_cached);
}

/* ── KEEP THE EXPIRING TASK RUNNING (Gen 6) ──────────────────────────────
 * ops.dispatch() runs before the kernel re-queues a task whose slice ended,
 * so up to Gen 5 the head of the LLC DSQ always won, even when it sorted
 * after the expiring task: a T2 render thread past its 4ms slice handed the
 * CPU to a T3 task that had queued a moment earlier, then waited behind it
 * (T2 enqueues never kick). This compares first, the way LAVD's
 * consume_prev()/bpfland keep @prev: if the deadline the expiring task
 * would get on re-queue (now + its tier budget) is no later than the head's,
 * it keeps the CPU for another requeue_slice(). Setting @prev's slice is the
 * kernel's documented "keep running @prev" signal (balance_one() on 6.12,
 * scx_dispatch_sched() on current kernels).
 *
 * A lock holder still inside its protection window is kept once per run
 * regardless of the queue (LAVD keeps a lock holder unconditionally; here it
 * is bounded to one extra slice).
 *
 * Not kept: tasks that called sched_yield() (CAKE_XF_YIELDED), and
 * everything when the local LLC DSQ is empty — that case is unchanged
 * (cross-LLC steal, else the kernel keeps @prev on a default slice). */
static __always_inline bool keep_prev_running(struct task_struct *prev, u32 llc)
{
    if (!(prev->scx.flags & SCX_TASK_QUEUED))
        return false;

    struct imperator_task_ctx *tctx = bpf_task_storage_get(&task_ctx, prev, 0, 0);
    if (!tctx || !tctx->last_run_at)
        return false;

    u32 packed = imperator_relaxed_load_u32(&tctx->packed_info);
    if (packed & XFLAG(CAKE_XF_YIELDED)) {
        __sync_fetch_and_and(&tctx->packed_info, ~XFLAG(CAKE_XF_YIELDED));
        return false;
    }

    struct task_struct *head = __COMPAT_scx_bpf_dsq_peek(LLC_DSQ_BASE + llc);
    if (!head)
        return false;

    u64 now = scx_bpf_now();
    u32 now32 = (u32)now;
    u8  tier = CAKE_TIER_IDX(GET_TIER_RAW(packed));
    u64 prev_dl = tier_deadline(now, tier, 0);
    bool lock_keep = false;

    if (unlikely((packed & FLOWFLAG(CAKE_FLAG_LOCK_HOLDER)) && !tctx->lock_grace)) {
        u32 cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
        lock_keep = lock_window_open(
            imperator_relaxed_load_u32(&mega_mailbox[cpu].lock_since), now32);
    }

    if (!lock_keep && head->scx.dsq_vtime < prev_dl)
        return false;

    /* Close the finished segment as if the task had stopped and been picked
     * again: its CPU time joins the burst (classification still sees the
     * whole wake-to-sleep run) and is charged to the DRR++ deficit, and the
     * bout clock restarts so imperator_tick measures the new slice. */
    u32 seg_us = (u32)(now32 - tctx->last_run_at) >> 10;
    u32 acc = (u32)tctx->burst_acc_us + seg_us;
    tctx->burst_acc_us = acc > 0xFFFF ? 0xFFFF : (u16)acc;

    u32 fused = tctx->deficit_avg_fused;
    u16 deficit = EXTRACT_DEFICIT(fused);
    deficit = (seg_us >= deficit) ? 0 : deficit - (u16)seg_us;
    tctx->deficit_avg_fused = PACK_DEFICIT_AVG(deficit, EXTRACT_AVG_RT(fused));

    tctx->last_run_at = now32 ? now32 : 1;
    if (lock_keep)
        tctx->lock_grace = 1;

    /* A lock holder gets one short extension (the protection window), not
     * a full slice: a T0 task may be waiting behind it. */
    scx_bpf_task_set_slice(prev, lock_keep ? LOCK_WINDOW_NS : requeue_slice(tctx));

    if (enable_stats) {
        struct imperator_stats *s = get_local_stats();
        if (s) {
            if (lock_keep)
                s->nr_lock_holder_protects++;
            else
                s->nr_prev_kept++;
        }
    }
    return true;
}

/* Dispatch: per-LLC DSQ scan with bitmask-driven cross-LLC stealing.
 * Direct-dispatched tasks (SCX_DSQ_LOCAL_ON) bypass this callback entirely —
 * kernel handles them natively. Only tasks that went through
 * imperator_enqueue → per-LLC DSQ arrive here.
 *
 * FIX (audit): steal mask is now built by reading per-LLC nonempty[] bytes
 * rather than a single shared llc_nonempty_mask word.  This eliminates the
 * cross-LLC cache-line bounce on every enqueue while keeping the steal scan
 * O(nr_llcs) — at most 8 reads, each from a distinct LLC-local cache line. */
void BPF_STRUCT_OPS(imperator_dispatch, s32 raw_cpu, struct task_struct *prev)
{
    u32 my_llc = cpu_llc_id[raw_cpu & (CAKE_MAX_CPUS - 1)];

    if (prev && keep_prev_running(prev, my_llc & (CAKE_MAX_LLCS - 1)))
        return;

    /* Local LLC first — zero cross-CCD contention in steady state */
    if (scx_bpf_dsq_move_to_local(LLC_DSQ_BASE + my_llc, 0))
        return;

    /* audit/G5-6: move_to_local() also fails when every queued task is affine
     * to other CPUs; clearing the flag then hides those tasks from the steal
     * scan. Clear it only when the DSQ is really empty. */
    if (!scx_bpf_dsq_nr_queued(LLC_DSQ_BASE + my_llc))
        imperator_relaxed_store_u8(&llc_nonempty[my_llc & (CAKE_MAX_LLCS - 1)].nonempty, 0);

    /* RODATA gate: single-LLC systems skip steal entirely (Rule 5).
     * JIT DCEs the loop below when nr_llcs == 1. */
    if (nr_llcs <= 1)
        return;

    /* Build steal mask from per-LLC nonempty bytes.
     * Each read is a separate cache line — no false sharing.
     * Stale set flags cause at most one failed dsq_move per race — harmless.
     *
     * FIX (audit): Loop to nr_llcs (RODATA const), not CAKE_MAX_LLCS.
     * On a dual-CCD system with nr_llcs=2 the old loop ran 8 iterations
     * with 6 unconditional i < nr_llcs misses.  The JIT treats nr_llcs as a
     * bounded constant and unrolls/DCEs the body accordingly. */
    /* FIX (gap/etd-steal): ETD-cost-aware work stealing.
     * When llc_etd_cost[] has been populated by userspace after ETD calibration,
     * prefer stealing from the lowest-latency source LLC first.  This reduces
     * cross-CCD cache-miss penalties on dual-CCD systems (e.g. 9950X) by trying
     * the cheaper CCD before the more expensive one.
     *
     * Correctness: all LLCs are still attempted — cheapest_llc is tried first,
     * then remaining LLCs in BSF order.  No work is ever skipped or dropped.
     * When costs are all 0 (pre-calibration), cheapest_llc sentinel remains at
     * nr_llcs and the loop degrades to the original index-order behaviour. */
    u32 steal_mask   = 0;
    u32 cheapest_llc = nr_llcs;  /* sentinel: no ETD-preferred candidate */
    u8  min_cost     = 0;        /* 0 = no calibration data present */

    for (u32 i = 0; i < nr_llcs; i++) {
        if (i != my_llc &&
            imperator_relaxed_load_u8(&llc_nonempty[i].nonempty)) {
            /* audit/G5-6: threads_per_ccd depth gate removed. It compared the
             * number of *waiting* tasks against the CCD's thread count, so a
             * CPU going idle here refused to steal until 16 tasks (9950X)
             * were already queued on the other LLC, leaving queued work
             * behind idle CPUs for up to a full slice. ops.dispatch() only
             * reaches this point when the local LLC DSQ has nothing this CPU
             * can run. */
            steal_mask |= 1u << i;
            u8 c = llc_etd_cost[my_llc & (CAKE_MAX_LLCS - 1)][i & (CAKE_MAX_LLCS - 1)];
            /* Only update cheapest when ETD data is present (c > 0). */
            if (c > 0 && (min_cost == 0 || c < min_cost)) {
                min_cost     = c;
                cheapest_llc = i;
            }
        }
    }

    /* Steal from cheapest LLC first when ETD data is available */
    if (cheapest_llc < nr_llcs && min_cost > 0) {
        steal_mask &= ~(1u << cheapest_llc);
        if (scx_bpf_dsq_move_to_local(LLC_DSQ_BASE + cheapest_llc, 0))
            return;
        if (!scx_bpf_dsq_nr_queued(LLC_DSQ_BASE + cheapest_llc))
            imperator_relaxed_store_u8(&llc_nonempty[cheapest_llc & (CAKE_MAX_LLCS - 1)].nonempty, 0);
    }

    /* Try remaining LLCs in BSF order (original behaviour) */
    for (u32 i = 0; steal_mask && i < nr_llcs; i++) {
        /* i is a verifier-required trip-count bound; actual iteration is BSF-driven.
         * steal_mask bits are set only for indices in [0, nr_llcs) by the loop above,
         * so victim is always a valid LLC index — no bounds check needed. */
        u32 victim = BIT_SCAN_FORWARD_U32(steal_mask);
        steal_mask &= steal_mask - 1;  /* clear LSB */
        if (scx_bpf_dsq_move_to_local(LLC_DSQ_BASE + victim, 0))
            return;
        if (!scx_bpf_dsq_nr_queued(LLC_DSQ_BASE + victim))
            imperator_relaxed_store_u8(&llc_nonempty[victim & (CAKE_MAX_LLCS - 1)].nonempty, 0);
    }
}

/* DVFS RODATA LUT: Tier → CPU performance target (branchless via array index)
 * SCX_CPUPERF_ONE = 1024 = max hardware frequency. JIT constant-folds the array.
 *
 * DESKTOP POLICY: all tiers run at SCX_CPUPERF_ONE (100%).
 *
 * The previous T3=75% policy was a power-saving measure suited to laptops and
 * thermally-constrained systems.  On a desktop PC on mains power:
 *
 *   (1) The GPU is almost always the frame-time bottleneck, not the CPU.
 *       Throttling background (T3) tasks like shader compilation to 75%
 *       makes them take longer while the GPU idles — a pure loss.
 *
 *   (2) DVFS throttling below 100% interacts poorly with Ryzen Precision Boost:
 *       the CPPC2 driver translates SCX_CPUPERF to a frequency hint; a hint of
 *       768 on a 9800X3D can suppress Boost when the core is thermally unconstrained,
 *       losing 300-500MHz the hardware is willing to provide for free.
 *
 *   (3) T3 tasks that temporarily cross into T3 due to load spikes (shader compilation
 *       burst, asset streaming) are penalised at exactly the wrong moment.
 *
 *   (4) Deadline budgets (tier_deadline()) and the T0/T1 preemption kick are
 *       the mechanisms that bound how long T3 can hold back foreground work
 *       (the tick-side starvation preemption this point originally named
 *       could never fire and was removed in Gen 6). Frequency throttling
 *       was a blunt, second-order approximation that also hurt T3 throughput
 *       for no targeted benefit — it capped T3's *speed* uniformly instead of
 *       capping the *duration* foreground tasks actually wait on it.
 *       CAKE_DEFAULT_STARVATION_T3 (intf.h) has been tightened from 100ms to
 *       50ms specifically to compensate for T3 now running at full clock: an
 *       unthrottled T3 task makes more progress per ms of any given wait, so
 *       the wait itself needed a tighter ceiling to keep T3's worst-case
 *       impact on T0-T2 from growing when this table changed. See intf.h for
 *       the full rationale and the open A/B-validation item this still needs.
 *
 * On hybrid systems (has_hybrid=true): the existing cpuperf_cap-scaling path in
 * imperator_tick still applies on top of this table — E-core frequency is bounded
 * by the hardware's own cpuperf_cap, which is already ≤ SCX_CPUPERF_ONE. */
const u32 tier_perf_target[8] = {
    1024,  /* T0 Critical:    100% — IRQ, input, audio, network (<100µs) */
    1024,  /* T1 Interactive: 100% — compositor, physics, AI (<2ms) */
    1024,  /* T2 Frame:       100% — game render, encoding (<8ms) */
    1024,  /* T3 Bulk:        100% — compilation, background (≥8ms); desktop: no throttle */
    1024, 1024, 1024, 1024,  /* padding — safe via CAKE_TIER_IDX & 7 */
};

/* FIX (audit/F-02): dsq_hint encoding — was (target >> 2), collided with the
 * BSS-zero "unset" sentinel whenever a real target encoded to 0.
 *
 * PROBLEM this fixes: 1024 (SCX_CPUPERF_ONE) >> 2 = 256, which truncates to
 * a u8 as 0 — identical to the BSS-zero value every mailbox starts at before
 * its first DVFS write.  Once desktop policy made every entry in
 * tier_perf_target[] equal to 1024 (see table above), *every* real target a
 * CPU could ever compute also encoded to 0.  The hysteresis check
 * (cached_perf != target_cached) was therefore permanently "0 != 0" — false
 * on the very first tick, and every tick after — so scx_bpf_cpuperf_set()
 * was never called on a non-hybrid system: not once, for the life of the
 * scheduler.  Two comments in this codebase documented the *old* table (T3
 * at 75% => dsq_hint=192, correctly distinct from 0) and were never updated
 * when the table changed to all-1024; the hysteresis they describe stopped
 * matching the code the moment that happened.
 *
 * FIX: widen the shift to >>3 and add a +1 offset.  target ranges [0,1024]
 * (or [0,1024] scaled by cap on hybrid systems, still within that range), so
 * (target >> 3) ranges [0,128] and +1 gives [1,129] — comfortably inside a
 * u8 (max 255) with zero risk of ever landing back on 0.  0 is now reserved
 * exclusively for "never set"; every real target, including 1024, encodes to
 * a nonzero value distinct from the unset sentinel.  Cost: hysteresis now
 * buckets in units of 8 (out of a 1024-unit range, i.e. <0.8% resolution
 * loss) instead of 4 — negligible for a cache whose only job is deciding
 * whether to re-issue the kfunc, and a small, bounded price for eliminating
 * the collision for every possible target value, not just the current
 * all-1024 desktop table (a future profile that reintroduces per-tier
 * throttling will not silently reopen this bug). */
#define DSQ_HINT_UNSET(v)       ((v) == 0)
#define DSQ_HINT_ENCODE(target) ((u8)(((target) >> 3) + 1))

void BPF_STRUCT_OPS(imperator_tick, struct task_struct *p)
{
    /* Register pin p to r6 to avoid stack spills */
    register struct task_struct *p_reg asm("r6") = p;
    register struct imperator_task_ctx *tctx_reg asm("r7") = get_task_ctx(p_reg, false);
    register u32 cpu_id_reg asm("r8") = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);

    u32 now = (u32)scx_bpf_now();

    /* A preemption kick that did not lead to a task switch (dispatch kept the
     * task, or another CPU took the queued work first) leaves this CPU's
     * claim bit set; release it so the CPU can be a victim again. */
    u64 my_bit = 1ULL << cpu_id_reg;
    if (unlikely(imperator_relaxed_load_u64(&kick_pending_mask) & my_bit))
        __sync_fetch_and_and(&kick_pending_mask, ~my_bit);

    /* SAFETY GATE: tctx must exist and have been stamped */
    if (unlikely(!tctx_reg || tctx_reg->last_run_at == 0)) {
        if (tctx_reg) tctx_reg->last_run_at = now;
        return;
    }

    register u8 tier_reg asm("r9") = GET_TIER(tctx_reg);
    u64 runtime = (u64)(u32)(now - tctx_reg->last_run_at);
    struct mega_mailbox_entry *mbox = &mega_mailbox[cpu_id_reg];

    /* SLICE ENFORCEMENT: past next_slice with work waiting for this LLC.
     *
     * audit/G5-4: only when something can take the CPU. With nothing queued
     * the kernel keeps this task running on a refilled default slice without
     * ops.stopping()/ops.running(), so last_run_at stays put and an
     * unconditional preemption fired on every tick.
     *
     * Gen 6: the slice is zeroed instead of self-kicking (LAVD
     * preempt_at_tick()). The kernel reschedules after ops.tick() whenever
     * the slice is 0, so this is the same preemption without an irq_work
     * self-IPI. ops.dispatch() then decides whether the task really yields
     * (keep_prev_running()).
     *
     * The Gen 5 "PHASE 2" starvation check that used to follow is gone: its
     * threshold was the tier budget, which exceeds the slice in every
     * profile, so this branch always fired first and Phase 2 never could.
     * Bounded waiting comes from deadline ordering. */
    if (unlikely(runtime > tctx_reg->next_slice)) {
        u32 tick_llc = cpu_llc_id[cpu_id_reg] & (CAKE_MAX_LLCS - 1);
        if (scx_bpf_dsq_nr_queued(LLC_DSQ_BASE + tick_llc) > 0 ||
            scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL) > 0) {
            scx_bpf_task_set_slice(p_reg, 0);
            if (enable_stats) {
                struct imperator_stats *s = get_local_stats();
                if (s) s->nr_tick_preempts_tier[tier_reg & (CAKE_TIER_MAX - 1)]++;
            }
        }
    }

    /* MEGA-MAILBOX: re-publish the running tier (imperator_running already
     * did; this is a no-op compare unless something overwrote it). */
    u8 new_flags = (u8)(MBOX_VALID_FLAG | (tier_reg & MBOX_TIER_MASK));
    if (imperator_relaxed_load_u8(&mbox->flags) != new_flags)
        imperator_relaxed_store_u8(&mbox->flags, new_flags);

    /* DVFS: tier → performance target, written only when it changes.
     * Runs in tick (rq-locked) = ~15-20ns vs ~30-80ns unlocked in running.
     *
     * Hybrid scaling: on Intel P/E-core systems, scale target by each core's
     * cpuperf_cap so E-cores don't get over-requested. JIT eliminates this
     * branch entirely on non-hybrid CPUs (has_hybrid = false in RODATA). */
    u32 target = tier_perf_target[CAKE_TIER_IDX(tier_reg)];
    if (has_hybrid) {
        u32 cap = scx_bpf_cpuperf_cap(cpu_id_reg);
        target = (target * cap) >> 10;  /* scale by capability (1024 = 100%) */
    }
    u8 cached_perf = imperator_relaxed_load_u8(&mbox->dsq_hint);
    u8 target_cached = DSQ_HINT_ENCODE(target);
    if (DSQ_HINT_UNSET(cached_perf) || cached_perf != target_cached) {
        scx_bpf_cpuperf_set(cpu_id_reg, target);
        imperator_relaxed_store_u8(&mbox->dsq_hint, target_cached);
    }
}

/* Task started running — stamp last_run_at for runtime measurement and
 * eagerly publish tier to mega_mailbox + tier_cpu_mask.
 *
 * [D] s6: Set this CPU's bit in tier_cpu_mask for the new task's tier.
 * imperator_stopping owns all clears; running only sets — no double-ownership.
 *
 * DVFS moved to imperator_tick where rq lock is held (cpuperf_set ~15-20ns vs
 * ~30-80ns unlocked here). Saves ~44-84 cycles per context switch. */
void BPF_STRUCT_OPS(imperator_running, struct task_struct *p)
{
    struct imperator_task_ctx *tctx = get_task_ctx(p, false);
    if (!tctx)
        return;
    tctx->last_run_at = (u32)scx_bpf_now();

    /* C2-Infra: Compute and update per-task dispatch latency EWMA.
     *
     * Dispatch latency = time from imperator_enqueue to imperator_running.
     * Measured as (last_run_at - enqueue_time) — both are u32 truncations of
     * scx_bpf_now(), so the subtraction wraps correctly for any latency < 4.3s.
     *
     * Guard: skip when enqueue_time == 0.  Two cases produce a zero stamp:
     *   (a) Task took the direct-dispatch path (SCX_DSQ_LOCAL_ON via idle or
     *       SYNC wakeup) — imperator_enqueue did not run, no stamp was written.
     *   (b) Task was just allocated (alloc_task_ctx_cold) or exec'd/forked —
     *       field initialized to 0.
     *   (c) Task previously ran via the DSQ path (stamp was consumed and reset
     *       to 0 below) and then woke via SYNC — stamp is still 0 from reset.
     * In all cases 0 means "no valid stamp for this dispatch" and the EWMA must
     * not be updated.
     *
     * FIX (audit/Finding-7): After updating the EWMA, reset enqueue_time to 0.
     * Without this reset, a task that alternates DSQ→SYNC wakeups would carry
     * a stale enqueue_time from the DSQ dispatch into the subsequent SYNC
     * dispatch.  imperator_running would then compute (last_run_at - stale_T1),
     * measuring seconds rather than microseconds and injecting a 65ms-clamped
     * outlier into jitter_ewma_us.  At α=1/8 one such outlier inflates the EWMA
     * by ~8× and takes ~56 subsequent samples to decay.
     *
     * Reset follows the CAKE_FLOW_IRQ_WAKE one-shot consume pattern: the field
     * is zeroed in the same block that uses it, making the lifecycle explicit.
     *
     * EWMA: α = 1/8, symmetric (no directional bias unlike avg_runtime_us).
     *   new = (old × 7 + sample) >> 3
     * Computed entirely in u32: old_ewma ≤ 65535, lat_us may reach ~4M for a
     * pathological u32 wrap; the intermediate product fits in u32 (max ~4.65M
     * < 2^32).  The clamp below is load-bearing for the lat_us > 65535 case —
     * not just defensive.
     *
     * Latency in nanoseconds is shifted right by 10 (÷1024 ≈ ÷1000) to convert
     * to approximate microseconds, matching the convention used for runtime_us
     * throughout the scheduler. */
    if (tctx->enqueue_time != 0) {
        u32 lat_ns   = tctx->last_run_at - tctx->enqueue_time;
        u32 lat_us   = lat_ns >> 10;   /* ns → ~µs (÷1024 ≈ ÷1000) */
        u32 old_ewma = (u32)tctx->jitter_ewma_us;
        /* α=1/8: max intermediate = 65535*7 + 4194303 = 4653048 < 2^32, no overflow */
        u32 new_ewma = (old_ewma * 7 + lat_us) >> 3;
        tctx->jitter_ewma_us = (u16)(new_ewma > 0xFFFF ? 0xFFFF : new_ewma);
        tctx->enqueue_time   = 0;  /* Consume stamp — prevents stale reads on next wakeup */

        /* W4 / C2-Infra: Accumulate jitter sample into per-CPU stats aggregates.
         * TUI computes mean_jitter_us = nr_jitter_ewma_sum / nr_jitter_ewma_count
         * across all CPUs to surface scheduling latency without a BPF iterator.
         * Uses the post-clamp EWMA value (not lat_us) so outliers are smoothed
         * by the EWMA before entering the aggregate — the mean reflects the
         * per-task steady-state latency, not transient spikes. */
        if (enable_stats) {
            struct imperator_stats *s = get_local_stats();
            if (s) {
                s->nr_jitter_ewma_sum   += (u64)tctx->jitter_ewma_us;
                s->nr_jitter_ewma_count += 1;
            }
        }
    }

    u32 run_cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
    struct mega_mailbox_entry *mbox = &mega_mailbox[run_cpu];
    u8 tier = CAKE_TIER_IDX(GET_TIER(tctx));

    /* Gen 6: a new task is running here, so any preemption kick aimed at
     * this CPU has been served; release the claim. */
    u64 run_bit = 1ULL << run_cpu;
    if (unlikely(imperator_relaxed_load_u64(&kick_pending_mask) & run_bit))
        __sync_fetch_and_and(&kick_pending_mask, ~run_bit);

    /* FIX (audit): Eagerly publish the task's tier to mega_mailbox so that
     * waker-tier inheritance in imperator_enqueue sees the correct tier from the
     * very first nanosecond of this task's run, not after its first tick.
     *
     * imperator_tick updates the mailbox at HZ intervals (1–4ms).  Any task woken
     * by this CPU in the window between context switch and the first tick
     * inherited the *previous* task's tier from the mailbox — the wrong value
     * at the worst time (right after a T0 audio thread is scheduled, the
     * mailbox might still show T3 from the bulk task it preempted).
     *
     * FIX (W1): Always OR in MBOX_VALID_FLAG (bit 7) when writing the tier.
     * CAKE_TIER_CRITICAL = 0 encodes as tier bits = 0x00; without the valid flag
     * a T0-running CPU writes 0x00 — identical to the BSS-zero unwritten state —
     * and the guard in imperator_enqueue cannot distinguish "T0 waker" from
     * "mailbox never written."  With MBOX_VALID_FLAG, T0 wakers write 0x80,
     * T1 wakers write 0x81, T2 write 0x82.  MBOX_GET_TIER masks bit 7 off
     * (MBOX_TIER_MASK = 0x03), so existing tier extraction is unaffected.
     * Cost: one conditional relaxed store per context switch (~2 cycles). */
    u8 cur_flags = imperator_relaxed_load_u8(&mbox->flags);
    u8 new_flags = (u8)(MBOX_VALID_FLAG | (cur_flags & ~MBOX_TIER_MASK) | tier);
    if (cur_flags != new_flags)
        imperator_relaxed_store_u8(&mbox->flags, new_flags);

    /* [D] s6: Mark this CPU as running a task of 'tier'.
     * BPF_ATOMIC_OR: single instruction, not a CAS loop.  Each CPU writes
     * only its own bit (1ULL << run_cpu) — no two CPUs contend on the same
     * bit.  The word-level atomic prevents torn read-modify-write when two
     * CPUs in different tiers update the same u64 simultaneously. */
    __sync_fetch_and_or(&tier_cpu_mask[tier & (CAKE_TIER_MAX - 1)], 1ULL << run_cpu);
}

/* Precomputed hysteresis gate tables (RODATA — JIT constant-folds these).
 * _demote[i]: standard gate — task at or above this average demotes past tier i.
 * _promote[i]: 90% of gate — task must be clearly faster to earn promotion.
 * Eliminates 3 runtime divisions per reclassify call. */
static const u16 tier_gate_demote[3]  = { TIER_GATE_T0, TIER_GATE_T1, TIER_GATE_T2 };
static const u16 tier_gate_promote[3] = {
    TIER_GATE_T0 - TIER_GATE_T0 / 10,   /* 90 */
    TIER_GATE_T1 - TIER_GATE_T1 / 10,   /* 1800 */
    TIER_GATE_T2 - TIER_GATE_T2 / 10,   /* 7200 */
};

/* S5: 1.5× tier-gate overrun thresholds.
 * A task consistently exceeding its tier gate triggers forced demotion.
 * 1.5× rather than 1.0× avoids false-triggering on normal EWMA bounce near
 * the boundary.  T3 entry is 0: bulk tasks have no gate to exceed. */
static const u16 tier_overrun_gate[4] = {
    TIER_GATE_T0 + TIER_GATE_T0 / 2,   /* T0: 150µs  */
    TIER_GATE_T1 + TIER_GATE_T1 / 2,   /* T1: 3000µs */
    TIER_GATE_T2 + TIER_GATE_T2 / 2,   /* T2: 12000µs */
    0,                                   /* T3: no check */
};

/* ── FRAME-CADENCE CAP (Gen 6, from LAVD's wait_freq signal) ──────────────
 * A thread that sleeps at least ~30 times a second and spends at least 1/8 of
 * each period asleep is frame-paced: a game main/simulation thread running
 * 8-14ms of a 16.6ms frame, an encoder keeping pace with capture. By burst
 * length alone it is T3, which put it behind every T2 task by the T2→T3
 * budget gap (80ms on Default) and made it the first victim of every T0/T1
 * preemption kick. Such a task is held at T2.
 *
 * Bulk work does not match: a compiler or a worker draining a job queue
 * either sleeps rarely (period ≫ 34ms) or barely at all between jobs (duty
 * ≈ 100%). LAVD gets the same separation from wait_freq/wake_freq feeding
 * its latency-criticality score. */
static __always_inline u8 cadence_cap(u8 tier, u16 avg_rt, u16 cadence)
{
    if (tier == CAKE_TIER_BULK && cadence && cadence <= FRAME_CADENCE_MAX_US &&
        avg_rt < cadence - (cadence >> 3))
        return CAKE_TIER_FRAME;
    return tier;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * AVG_RUNTIME CLASSIFICATION + DRR++: Dynamic tier reclassification on every stop.
 * CPU analog of network CAKE's flow classification:
 * - Sparse flows (audio, input) → short bursts + yield → settle at T0-T1
 * - Bulk flows (compilation, renders) → run until preempted → demote to T2-T3
 * - Mixed flows (game logic) → medium bursts → settle at T1-T2
 *
 * This is the engine that makes tier-encoded vtime and per-tier starvation
 * actually differentiate traffic. Without it, all userspace tasks compete
 * at the same tier.
 * ═══════════════════════════════════════════════════════════════════════════ */
static __attribute__((noinline))
void reclassify_task_cold(struct imperator_task_ctx *tctx, bool runnable)
{
    u32 packed = imperator_relaxed_load_u32(&tctx->packed_info);

    /* ── RUNTIME MEASUREMENT ── */
    u32 now = (u32)scx_bpf_now();
    u32 last_run = tctx->last_run_at;
    if (!last_run)
        return;  /* Never ran — skip (safety gate) */

    u32 runtime_raw = now - last_run;

    /* FIX (audit/F-01): the Gap-1 post-sleep recovery heuristic used to live
     * here, gated on `!runnable`.  It has been RELOCATED to imperator_enqueue.
     *
     * reclassify_task_cold's only caller is imperator_stopping, which writes
     * tctx->sleep_entry_time for *this* stop event immediately before calling
     * it — so the value read here was always "now," never a timestamp that
     * survived from a prior sleep through an intervening wakeup, and
     * tctx->enqueue_time is unconditionally 0 at this point (already consumed
     * by imperator_running, or never set on the direct-dispatch path). The
     * computed "sleep_ns" was therefore `0 - sleep_entry_time_just_written`,
     * a u32 wraparound of the current timestamp with no relationship to real
     * elapsed sleep time — it exceeded the 500ms threshold on the large
     * majority of *all* blocking events, not just genuine long sleeps.
     *
     * The fix needs sleep_entry_time (stamped at sleep-start, in
     * imperator_stopping) compared against a timestamp taken at the task's
     * actual next wakeup — that pairing only exists in imperator_enqueue,
     * where enqueue_time is stamped. See the "Gap-1 post-sleep recovery"
     * block there for the corrected mechanism; nothing here depends on it. */

    u32 runtime_us = runtime_raw >> 10;  /* ns → ~μs (÷1024 ≈ ÷1000) */

    /* Clamp to u16 max for EWMA field (65ms max, more than any reasonable burst) */
    u16 bout_us = runtime_us > 0xFFFF ? 0xFFFF : (u16)runtime_us;

    /* audit/G5-2: classify on the burst since the task last slept, not on
     * this bout. A preempted bout ends at the scheduler's own slice boundary
     * (flat quantum_ns on the re-enqueue path, rounded up to the tick), so
     * per-bout samples pulled every CPU-bound task to ~2-4ms: T3 hogs were
     * promoted to T2 after one contended bout and T1-seeded hogs never left
     * T1/T2. An unfinished burst is a lower bound, so on a preemption it may
     * only raise avg_runtime (LAVD: max(avg_runtime, acc_runtime) in
     * calc_sum_runtime_factor()). DRR++ deficit still consumes per bout. */
    u32 burst_us = (u32)tctx->burst_acc_us + bout_us;
    u16 rt_clamped = burst_us > 0xFFFF ? 0xFFFF : (u16)burst_us;
    tctx->burst_acc_us = runnable ? rt_clamped : 0;

    /* ── GRADUATED BACKOFF ──
     * When tier has been stable for 3+ consecutive stops, throttle reclassify
     * frequency based on current tier. T0 tasks (IRQ/input) almost never
     * change → recheck every 1024th stop. T3 tasks (bulk) may transition
     * → recheck every 16th stop. Uses per-task counter + RODATA masks. */
    u8 stable = (packed >> SHIFT_STABLE) & 3;
    if (stable == 3) {
        /* FIX (#2 / #9): EWMA computation moved inside the early-return branch.
         *
         * Previously (pre-#2): EWMA arithmetic was hoisted above the counter-mask
         * check, so ~10 instructions ran unconditionally and their outputs were
         * silently discarded on every periodic-fallthrough boundary — pure dead work
         * every 16th stop for T3, every 128th for T1, every 1024th for T0.
         *
         * FIX (#9) single-EWMA guarantee is still intact: the computation only runs
         * inside the early-return branch (committed + returned) OR in the full path
         * below (committed + continues).  Never both in the same call.
         *
         * FIX (audit): CAKE_TIER_IDX() used for all tier array accesses — canonical
         * bounds-check matching the _Static_assert in intf.h. */
        u8 tier = (packed >> SHIFT_TIER) & MASK_TIER;
        u16 mask = tier_recheck_mask[CAKE_TIER_IDX(tier)];
        u16 counter = tctx->reclass_counter + 1;
        tctx->reclass_counter = counter;
        if (counter & mask) {
            /* Not time for full recheck — compute EWMA and return. */
            u32 old_fused = tctx->deficit_avg_fused;
            u16 avg_rt = EXTRACT_AVG_RT(old_fused);
            /* Asymmetric EWMA: promote fast (α=1/4), demote cautiously (α=1/16).
             * Gaming threads spike during loads then recover — fast promotion
             * restores T0/T1 priority within ~4 bouts instead of ~16. */
            u16 new_avg;
            if (rt_clamped < avg_rt)
                new_avg = runnable ? avg_rt
                                   : avg_rt - (avg_rt >> 2) + (rt_clamped >> 2);  /* promote α=1/4 */
            else
                new_avg = avg_rt - (avg_rt >> 4) + (rt_clamped >> 4);  /* demote  α=1/16 */
            u16 deficit = EXTRACT_DEFICIT(old_fused);
            deficit = (bout_us >= deficit) ? 0 : deficit - bout_us;

            u32 new_fused = PACK_DEFICIT_AVG(deficit, new_avg);
            if (new_fused != old_fused)
                tctx->deficit_avg_fused = new_fused;

            /* Spot-check: would new EWMA classify to a different tier?
             * Uses hysteresis-adjusted gates so spot-check agrees exactly
             * with full reclassify logic. Only resets stability when a genuine
             * tier change is imminent. Zero false triggers from normal frame
             * variance. */
            u16 g0 = (tier > 0) ? tier_gate_promote[0] : tier_gate_demote[0];
            u16 g1 = (tier > 1) ? tier_gate_promote[1] : tier_gate_demote[1];
            u16 g2 = (tier > 2) ? tier_gate_promote[2] : tier_gate_demote[2];
            u8 spot_tier;
            if      (new_avg < g0) spot_tier = 0;
            else if (new_avg < g1) spot_tier = 1;
            else if (new_avg < g2) spot_tier = 2;
            else                   spot_tier = 3;
            spot_tier = cadence_cap(spot_tier, new_avg, tctx->cadence_us);

            if (spot_tier != tier) {
                u32 reset = packed & ~((u32)3 << SHIFT_STABLE);
                imperator_relaxed_store_u32(&tctx->packed_info, reset);
                tctx->reclass_counter = 0;
            }
            return;
        }
        /* Fall through → periodic full reclassify.
         * tctx->deficit_avg_fused is unmodified above — full path reads the
         * original value and applies EWMA exactly once. */
    }

    /* ── FULL RECLASSIFICATION ── */

    /* ── EWMA RUNTIME UPDATE ── */
    /* Asymmetric decay: promote fast (α=1/4 ≈ 4 bouts), demote cautiously
     * (α=1/16 ≈ 16 bouts). Gaming threads spike during level loads then
     * recover — fast promotion restores T0/T1 priority without waiting 8+
     * bouts. Symmetric 1/8 allowed loading screens to permanently demote
     * game threads for the remainder of the session. */
    u32 old_fused = tctx->deficit_avg_fused;
    u16 avg_rt = EXTRACT_AVG_RT(old_fused);
    u16 new_avg;
    if (rt_clamped < avg_rt)
        new_avg = runnable ? avg_rt
                           : avg_rt - (avg_rt >> 2) + (rt_clamped >> 2);  /* promote α=1/4 */
    else
        new_avg = avg_rt - (avg_rt >> 4) + (rt_clamped >> 4);  /* demote  α=1/16 */

    /* ── DRR++ DEFICIT TRACKING ── */
    /* Each execution bout consumes deficit. When deficit exhausts, clear the
     * new-flow flag → task loses its priority bonus within the tier.
     * Initial deficit = quantum + new_flow_bonus ≈ 10ms of credit. */
    u16 deficit = EXTRACT_DEFICIT(old_fused);
    deficit = (bout_us >= deficit) ? 0 : deficit - bout_us;

    /* Pre-compute deficit_exhausted before rt_clamped/deficit die (Rule 36) */
    bool deficit_exhausted = (deficit == 0 && (packed & ((u32)CAKE_FLOW_NEW << SHIFT_FLAGS)));

    /* Write fused deficit + avg_runtime (MESI-friendly: skip if unchanged) */
    u32 new_fused = PACK_DEFICIT_AVG(deficit, new_avg);
    if (new_fused != old_fused)
        tctx->deficit_avg_fused = new_fused;

    /* ── HYSTERESIS TIER CLASSIFICATION ──
     * Precomputed gate tables (RODATA) eliminate runtime division.
     * To PROMOTE (lower tier): avg must be 10% below the gate.
     * To DEMOTE  (higher tier): standard gate — fast demotion.
     * Asymmetric by design: give more CPU time quickly, take back cautiously. */
    u8 old_tier = (packed >> SHIFT_TIER) & MASK_TIER;
    u8 new_tier;

    u16 g0 = (old_tier > 0) ? tier_gate_promote[0] : tier_gate_demote[0];
    u16 g1 = (old_tier > 1) ? tier_gate_promote[1] : tier_gate_demote[1];
    u16 g2 = (old_tier > 2) ? tier_gate_promote[2] : tier_gate_demote[2];

    if      (new_avg < g0) new_tier = 0;
    else if (new_avg < g1) new_tier = 1;
    else if (new_avg < g2) new_tier = 2;
    else                   new_tier = 3;

    /* ── HARD-DEMOTE CAP (runaway task safety) ──
     * FIX (audit): The asymmetric EWMA (demote α=1/16) is intentionally slow to
     * prevent transient spikes from permanently demoting game threads.  The
     * downside is a task that genuinely runs long (e.g. a misbehaving physics
     * thread stuck in a loop) can spend up to ~128ms misclassified in T1/T2,
     * competing ahead of legitimate render threads.
     *
     * Cap: if avg_runtime has been above TIER_GATE_T2 × 3 (24ms) for 3+
     * consecutive stable stops, force T3 regardless of the stability counter.
     * The 3× multiplier avoids false-triggering on normal level-load spikes
     * (~8–16ms) while catching tasks that are genuinely bulk.  stable >= 3
     * ensures we've had at least 3 consistent EWMA bouts before forcing, so
     * a single anomalous 25ms burst won't cause premature demotion. */
    if (new_avg > (u16)(TIER_GATE_T2 * 3) && stable >= 3 && new_tier < CAKE_TIER_BULK)
        new_tier = CAKE_TIER_BULK;

    /* ── [H] s6: BIT-HISTORY OVERRUN DEMOTION ───────────────────────────────
     * overrun_count is an 8-bit shift register of the last 8 execution outcomes.
     * Each stop shifts left one position and inserts the current bout's result
     * in the LSB; the oldest result falls off the MSB.
     *
     *   bit = 1  →  that bout's rt_clamped exceeded 1.5× the tier gate
     *   bit = 0  →  that bout ran within the gate
     *
     * DEMOTION TRIGGER: __builtin_popcount(overrun_count) >= 4
     *   Fires when 4 of the last 8 bouts exceeded the gate.
     *
     * BEHAVIORAL SUPERSET OF THE ORIGINAL CONSECUTIVE COUNTER:
     *   4 consecutive overruns → hist=0b00001111 → popcount=4 ≥ 4 → DEMOTE ✓
     *   4 alternating overruns → popcount=4 ≥ 4 → DEMOTE ✓ (new capability)
     *   Original counter reset on every clean bout — alternating never fired.
     *
     * THRESHOLD CORRECTION vs previous patch: 5 → 4.
     *   With threshold 5: 4 consecutive overruns → popcount=4 < 5 → NO DEMOTE.
     *   That was a regression vs the original counter which fired at exactly 4.
     *   With threshold 4: parity restored; non-consecutive patterns gain coverage.
     *
     * Only checked for T0–T2; T3 tasks are already bulk.
     * COST: shift + OR + popcount ≈ 4 cycles (identical to original inc+compare). */
    if (old_tier < CAKE_TIER_BULK) {
        u16 og      = tier_overrun_gate[CAKE_TIER_IDX(old_tier)];
        u8  outcome = (rt_clamped > og) ? 1u : 0u;

        /* Shift register: oldest outcome falls off MSB, new enters LSB */
        u8 hist = (u8)((tctx->overrun_count << 1) | outcome);
        tctx->overrun_count = hist;

        if (__builtin_popcount((unsigned int)hist) >= 4) {
            /* Force-demote by one tier; floor at CAKE_TIER_BULK.
             * We are inside (old_tier < CAKE_TIER_BULK) so old_tier+1 is safe. */
            u8 forced = (u8)(old_tier + 1);
            if (new_tier < forced)
                new_tier = forced;
            tctx->overrun_count = 0;
            stable = 0;  /* reset so new_stable below starts from 0 */
        }
    }

    /* ── FRAME-CADENCE CAP (Gen 6) ── applied last, so neither the hard-demote
     * cap nor overrun demotion can push a frame-paced thread into T3. */
    if (new_tier == CAKE_TIER_BULK) {
        new_tier = cadence_cap(new_tier, new_avg, tctx->cadence_us);
        if (new_tier != CAKE_TIER_BULK && enable_stats) {
            struct imperator_stats *s = get_local_stats();
            if (s) s->nr_cadence_caps++;
        }
    }

    /* ── WRITE PACKED_INFO (MESI-friendly: skip if unchanged) ── */
    bool tier_changed = (new_tier != old_tier);

    /* Tier-stability counter: increment toward 3 if tier held, reset on change.
     * When stable==3, subsequent calls take the graduated backoff path. */
    u8 new_stable = tier_changed ? 0 : ((stable < 3) ? stable + 1 : 3);

    if (tier_changed || deficit_exhausted || new_stable != stable) {
        u32 new_packed = packed;
        /* Fused tier+stable: bits [31:28] = [stable:2][tier:2]
         * Bitfield coalescing — 2 ops instead of 4 (Rule 24 mask fusion) */
        new_packed &= ~((u32)0xF << 28);
        new_packed |= (((u32)new_stable << 2) | (u32)new_tier) << 28;
        /* DRR++: Clear new-flow flag when deficit exhausted */
        if (deficit_exhausted)
            new_packed &= ~((u32)CAKE_FLOW_NEW << SHIFT_FLAGS);

        imperator_relaxed_store_u32(&tctx->packed_info, new_packed);
    }

    /* ── SLICE RECALCULATION (every bout) ──
     * next_slice always holds the tier's natural slice. Recomputed every
     * bout (not only on a tier change) since the Gen 5 burst-credit path
     * could leave an extended value behind; cheap on this cold path. */
    {
        u64 cfg = tier_configs[CAKE_TIER_IDX(new_tier)];
        u64 mult = UNPACK_MULTIPLIER(cfg);
        tctx->next_slice = (quantum_ns * mult) >> 10;
    }

    if (tier_changed)
        tctx->reclass_counter = 0;
}

/* Gen 6: ops.init_task removed. Its fork-inheritance and exec-reset branches
 * never ran: task storage is created in ops.enable, which runs after
 * ops.init_task, so the context lookup there always failed; and sched_ext
 * has no exec hook (init_task with !fork only fires when a task first enters
 * sched_ext, e.g. at scheduler load). Every task is seeded from its own nice
 * value in alloc_task_ctx_cold(), which is what the scheduler always did. */

/* Pre-allocate task context when a task enters scx control.
 * Fires once per task — not in the scheduling hot path.
 * Guarantees imperator_running/imperator_stopping never see a NULL context,
 * converting those null guards from live code paths to safety assertions. */
s32 BPF_STRUCT_OPS(imperator_enable, struct task_struct *p)
{
    get_task_ctx(p, true);
    return 0;
}

/* Task stopping — clear tier_cpu_mask bit BEFORE reclassification, then
 * run avg_runtime reclassification + DRR++ deficit tracking.
 *
 * [E] s6: ORDER IS CRITICAL.
 *   GET_TIER(tctx) before reclassify = the tier the task was running at
 *   = the tier whose bit is set in tier_cpu_mask = the correct bit to clear.
 *   After reclassify_task_cold(), GET_TIER returns the new post-EWMA tier. */
void BPF_STRUCT_OPS(imperator_stopping, struct task_struct *p, bool runnable)
{
    struct imperator_task_ctx *tctx = get_task_ctx(p, false);
    /* Skip tasks that have never been stamped by imperator_running. */
    if (!tctx || unlikely(!tctx->last_run_at))
        return;

    u32 stop_cpu  = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
    u8  stop_tier = CAKE_TIER_IDX(GET_TIER(tctx));
    __sync_fetch_and_and(&tier_cpu_mask[stop_tier & (CAKE_TIER_MAX - 1)],
                         ~(1ULL << stop_cpu));

    /* Gen 6: runnable == false does not mean the task went to sleep. The
     * kernel calls ops.stopping(p, false) for every dequeue of the running
     * task, including property changes (SCX_DEQ_SCHED_CHANGE: affinity,
     * nice, scheduling class, cgroup moves), after which the task is
     * re-enqueued still runnable. Up to Gen 5 each of those was treated as a
     * sleep: the burst was cut short, the short sample could promote the
     * task, and the post-sleep recovery clock started. In the VM test a pure
     * CPU spinner was cut every ~5ms this way and sat in T2 instead of T3.
     * A task that is really blocking has already left TASK_RUNNING; LAVD
     * makes the same distinction with SCX_DEQ_SLEEP in ops.quiescent(). */
    bool sleeping = !runnable && p->__state != 0 /* TASK_RUNNING */;

    /* ── One-shot state that must not outlive this run (Gen 6) ──
     *   LOCK_HOLDER  → cleared. If the task is not sleeping (preempted or
     *                  slice-expired while holding the lock), convert it to
     *                  CAKE_XF_LOCK_BOOST: one within-tier deadline advance on
     *                  the re-queue. A task that blocks is not boosted — it
     *                  most likely released the lock, and futex_wait()
     *                  returning 0 also flags plain condvar waiters.
     *   YIELDED      → cleared (only meaningful to the dispatch that follows
     *                  the yield).
     *   IRQ_WAKE     → cleared if somehow still set; it only applies to the
     *                  queued wakeup it was stamped for. */
    u32 packed = imperator_relaxed_load_u32(&tctx->packed_info);
    u32 clr = packed & (FLOWFLAG(CAKE_FLAG_LOCK_HOLDER) | FLOWFLAG(CAKE_FLOW_IRQ_WAKE) |
                        XFLAG(CAKE_XF_YIELDED));
    u32 set = 0;
    if (!sleeping && (packed & FLOWFLAG(CAKE_FLAG_LOCK_HOLDER)))
        set |= XFLAG(CAKE_XF_LOCK_BOOST);
    if (clr)
        __sync_fetch_and_and(&tctx->packed_info, ~clr);
    if (set)
        __sync_fetch_and_or(&tctx->packed_info, set);

    struct mega_mailbox_entry *mbox = &mega_mailbox[stop_cpu];
    if (imperator_relaxed_load_u32(&mbox->lock_since))
        imperator_relaxed_store_u32(&mbox->lock_since, 0);
    tctx->lock_grace = 0;

    /* Gap-1 / audit/F-01: stamp sleep_entry_time when the task genuinely
     * blocks; imperator_enqueue consumes it at the next queued wakeup to
     * measure the sleep (post-sleep recovery). Cleared when the task is
     * switched out while still runnable.
     *
     * Gen 6: every block also yields one cadence sample, the time since the
     * previous block (one full run + sleep cycle), averaged with α=1/4 into
     * cadence_us for the frame-cadence cap. */
    if (sleeping) {
        u32 now32 = (u32)scx_bpf_now();
        tctx->sleep_entry_time = now32;

        u32 last = tctx->last_sleep_at;
        if (last) {
            u32 period_us = (u32)(now32 - last) >> 10;
            u16 sample = period_us > 0xFFFF ? 0xFFFF : (u16)period_us;
            u16 cad = tctx->cadence_us;
            tctx->cadence_us = cad ? (u16)(cad - (cad >> 2) + (sample >> 2)) : sample;
        }
        tctx->last_sleep_at = now32 ? now32 : 1;
    } else {
        tctx->sleep_entry_time = 0;
    }

    reclassify_task_cold(tctx, !sleeping);
}

/* sched_yield() (Gen 6). Implementing ops.yield means the kernel no longer
 * zeroes the slice itself, so do that here, and flag the task so
 * keep_prev_running() lets the queue go first — a yielding spin-waiter
 * (Wine's NtYieldExecution/SwitchToThread) must not be handed the CPU back
 * ahead of the thread it is waiting for. Directed yield_to() is not
 * supported (returns false). */
bool BPF_STRUCT_OPS(imperator_yield, struct task_struct *from, struct task_struct *to)
{
    struct imperator_task_ctx *tctx = get_task_ctx(from, false);
    if (tctx && !(imperator_relaxed_load_u32(&tctx->packed_info) & XFLAG(CAKE_XF_YIELDED)))
        __sync_fetch_and_or(&tctx->packed_info, XFLAG(CAKE_XF_YIELDED));
    scx_bpf_task_set_slice(from, 0);
    return false;
}

/* Per-task line in the sched_ext debug dump (SysRq-D, or the dump printed
 * when the scheduler exits on an error). Gen 6, after LAVD's dump_task. */
void BPF_STRUCT_OPS(imperator_dump_task, struct scx_dump_ctx *dctx, struct task_struct *p)
{
    struct imperator_task_ctx *tctx = get_task_ctx(p, false);
    if (!tctx)
        return;

    u32 packed = imperator_relaxed_load_u32(&tctx->packed_info);
    u32 fused  = tctx->deficit_avg_fused;
    scx_bpf_dump("  \\_ imperator: tier=%u stable=%u avg_rt=%uus burst=%uus cadence=%uus "
                 "deficit=%uus slice=%lluns flags=0x%x overrun=0x%x\n",
                 GET_TIER_RAW(packed), (packed >> SHIFT_STABLE) & 3,
                 EXTRACT_AVG_RT(fused), tctx->burst_acc_us, tctx->cadence_us,
                 EXTRACT_DEFICIT(fused), tctx->next_slice,
                 (packed >> SHIFT_XFLAGS) & 0xFFF, tctx->overrun_count);
}

/* Initialize the scheduler.
 * [C] s6: Compute llc_cpu_mask from cpu_llc_id RODATA before any task runs.
 *
 * This eliminates the partial-deploy hazard: previously llc_cpu_mask had to
 * be written by the Rust loader; if that write was absent (e.g. rolling update
 * midway through deployment) the mask stayed all-zero and the O(1) bitmask
 * kick produced zero kicks without any error or warning.  Now imperator_init fills
 * it unconditionally from the already-correct cpu_llc_id RODATA. */
s32 BPF_STRUCT_OPS_SLEEPABLE(imperator_init)
{
    /* [C] Populate llc_cpu_mask from cpu_llc_id.
     * Loop is bounded by both nr_cpus (RODATA const, JIT treats as bounded)
     * and CAKE_MAX_CPUS (compile-time constant) — verifier sees a safe bound.
     * Plain |= is safe: imperator_init runs exactly once before any task is
     * scheduled, so no concurrent BPF program can read llc_cpu_mask yet. */
    for (u32 cpu = 0; cpu < nr_cpus && cpu < CAKE_MAX_CPUS; cpu++) {
        u32 llc = cpu_llc_id[cpu] & (CAKE_MAX_LLCS - 1);
        llc_cpu_mask[llc] |= 1ULL << cpu;
    }

    /* Create per-LLC DSQs — one per cache domain.
     * Single-CCD: 1 DSQ (single per-LLC DSQ).
     * Multi-CCD: N DSQs (eliminates cross-CCD lock contention).
     *
     * FIX (audit): Loop directly to nr_llcs rather than CAKE_MAX_LLCS with an
     * interior break. The original form was a verifier workaround for older
     * kernels that required compile-time-bounded loops; nr_llcs is a RODATA
     * const volatile that the JIT treats as a bounded constant. */
    for (u32 i = 0; i < nr_llcs; i++) {
        s32 ret = scx_bpf_create_dsq(LLC_DSQ_BASE + i, -1);
        if (ret < 0)
            return ret;
    }

    return 0;
}

/* Scheduler exit - record exit info */
void BPF_STRUCT_OPS(imperator_exit, struct scx_exit_info *ei)
{
    UEI_RECORD(uei, ei);
}

/* Lock-holder probes (fexit / tracepoint). Same compilation unit so they can
 * use task_ctx, mega_mailbox and the helpers above; see lock.bpf.c. */
#include "lock.bpf.c"

SCX_OPS_DEFINE(imperator_ops,
               .select_cpu     = (void *)imperator_select_cpu,
               .enqueue        = (void *)imperator_enqueue,
               .dispatch       = (void *)imperator_dispatch,
               .tick           = (void *)imperator_tick,
               .running        = (void *)imperator_running,
               .stopping       = (void *)imperator_stopping,
               .yield          = (void *)imperator_yield,
               .dump_task      = (void *)imperator_dump_task,
               .enable         = (void *)imperator_enable,
               .init           = (void *)imperator_init,
               .exit           = (void *)imperator_exit,
               .flags          = SCX_OPS_KEEP_BUILTIN_IDLE,
               .name           = "imperator");
