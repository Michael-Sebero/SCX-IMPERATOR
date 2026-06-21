// SPDX-License-Identifier: GPL-2.0
// Statistics module for scx_imperator - utilities for reading/formatting scheduler stats from BPF maps

/// Priority tier names (4-tier system classified by avg_runtime)
pub const TIER_NAMES: [&str; 4] = [
    "Critical",    // T0: <100µs
    "Interactive", // T1: <2ms
    "Frame",       // T2: <8ms
    "Bulk",        // T3: ≥8ms
];

/// C3: Burst credit stat counter indices within imperator_stats.
///
/// Field layout of imperator_stats (u64 fields, 0-indexed):
///   [0]     nr_new_flow_dispatches
///   [1]     nr_old_flow_dispatches
///   [2..5]  nr_tier_dispatches[4]
///   [6..9]  nr_starvation_preempts_tier[4]
///   [10]    nr_lock_holder_skips
///   [11]    nr_irq_wake_boosts
///   [12]    nr_waker_tier_boosts
///   [13]    nr_preempt_with_credit      ← C3 earning counter
///   [14]    nr_burst_credit_consumed    ← C3 consumption counter
///   [15]    nr_jitter_ewma_sum          ← C2-Infra dispatch latency sum (W4 fix)
///   [16]    nr_jitter_ewma_count        ← C2-Infra dispatch latency sample count
///   [17..31] _pad[15]
///
/// FIX (audit/Finding-4): Burst credit is accumulated AND consumed within the
/// same `imperator_enqueue` invocation — credit earned on a preemption event is
/// immediately consumed to extend the current dispatch's slice.  As a result:
///
///   consumed/credited ratio semantics:
///     ≈ 1.0  — steady state: each preemption earning credit also consumes it.
///     > 1.0  — task had residual credit from a prior preemption (cap was not
///              yet reached) that carried into the current earning event.  The
///              prior accumulation and the new accumulation were both consumed
///              in a single consumption event.
///     < 1.0  — CANNOT HAPPEN with the current implementation.  Credit earned
///              in call N is always consumed in the same call N.
///
/// The graduation gate criterion remains unchanged: nr_starvation_preempts_tier[2]
/// per second must decrease ≥20% under sustained T1+T2 competition before C3
/// graduates from Experimental to Accepted.
///
/// Note: the TUI reads these fields by struct field name, not by integer index,
/// so these constants are intentionally unused in code — they exist as the single
/// authoritative source of truth for field offsets, useful for external tooling
/// (bpftool, perf scripts, eBPF probes) that must address fields by offset.
/// `#[allow(dead_code)]` suppresses the Rust compiler warning for this reason.
#[allow(dead_code)]
pub const STAT_IDX_PREEMPT_WITH_CREDIT: usize = 13;
#[allow(dead_code)]
pub const STAT_IDX_BURST_CREDIT_CONSUMED: usize = 14;

/// C2-Infra: Dispatch latency telemetry stat counter indices within imperator_stats.
///
/// nr_jitter_ewma_sum / nr_jitter_ewma_count are accumulated in imperator_running
/// on every DSQ-path context switch where enqueue_time was non-zero.
/// TUI computes: mean_dispatch_latency_us = sum / count.
/// Both are per-CPU in BSS; summed across CPUs in aggregate_stats().
///
/// Same access pattern note as C3 constants above: read by field name in tui.rs,
/// these index constants exist for external tooling only.
#[allow(dead_code)]
pub const STAT_IDX_JITTER_EWMA_SUM: usize = 15;
#[allow(dead_code)]
pub const STAT_IDX_JITTER_EWMA_COUNT: usize = 16;
