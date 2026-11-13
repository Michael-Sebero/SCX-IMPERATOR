// SPDX-License-Identifier: GPL-2.0
// Statistics module for scx_imperator - utilities for reading/formatting scheduler stats from BPF maps

/// Priority tier names (4-tier system classified by avg_runtime)
pub const TIER_NAMES: [&str; 4] = [
    "Critical",    // T0: <100µs
    "Interactive", // T1: <2ms
    "Frame",       // T2: <8ms
    "Bulk",        // T3: ≥8ms
];

/// Field layout of imperator_stats (u64 fields, 0-indexed; see intf.h):
///   [0]      nr_new_flow_dispatches   wakeup dispatches
///   [1]      nr_old_flow_dispatches   re-queues (slice expiry, kicks, yields)
///   [2..5]   nr_tier_dispatches[4]
///   [6..9]   nr_tick_preempts_tier[4]
///   [10]     nr_lock_holder_protects
///   [11]     nr_irq_wake_boosts
///   [12]     nr_waker_tier_boosts
///   [13]     nr_preempt_kicks
///   [14]     nr_jitter_ewma_sum
///   [15]     nr_jitter_ewma_count
///   [16]     nr_prev_kept
///   [17]     nr_cadence_caps
///   [18..31] _pad[14]
///
/// The TUI reads fields by name; these indices exist for external tooling
/// (bpftool, perf scripts) that addresses the per-CPU array by offset.
#[allow(dead_code)]
pub const STAT_IDX_PREEMPT_KICKS: usize = 13;
#[allow(dead_code)]
pub const STAT_IDX_PREV_KEPT: usize = 16;
#[allow(dead_code)]
pub const STAT_IDX_CADENCE_CAPS: usize = 17;

/// C2-Infra: Dispatch latency telemetry stat counter indices within imperator_stats.
///
/// nr_jitter_ewma_sum / nr_jitter_ewma_count are accumulated in imperator_running
/// on every DSQ-path context switch where enqueue_time was non-zero.
/// TUI computes: mean_dispatch_latency_us = sum / count.
/// Both are per-CPU in BSS; summed across CPUs in aggregate_stats().
///
/// Same access pattern note as above: read by field name in tui.rs, these
/// index constants exist for external tooling only.
#[allow(dead_code)]
pub const STAT_IDX_JITTER_EWMA_SUM: usize = 14;
#[allow(dead_code)]
pub const STAT_IDX_JITTER_EWMA_COUNT: usize = 15;
