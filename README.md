## **I.M.P.E.R.A.T.O.R**

**Integrated · Multitiered · Priority · Execution · Ranked · Adaptive · Topology · Ordered · Runtime**

> **ABSTRACT**: `scx_imperator` is a BPF CPU scheduler built on [sched_ext](https://github.com/sched-ext/scx), designed for **gaming workloads** on modern AMD and Intel hardware. It classifies every task by observed runtime behavior and routes work through a 4-tier priority system high-priority tasks like audio callbacks and mouse input get CPU time first, bulk work like compilers gets it last.
>
> - **4-Tier Classification** Tasks sorted by asymmetric EWMA avg_runtime into Critical / Interactive / Frame / Bulk
> - **IRQ-Wake Boosting** Hardware wakeups (GPU vsync, audio DMA, network) immediately promote that task to T0 for one dispatch
> - **Waker Tier Inheritance** High-priority task waking a lower-priority one lifts the wakee's tier, keeping producer-consumer chains tight
> - **Lock-Holder Protection** Futex holders get scheduling priority and starvation skips to release locks faster, unblocking waiters sooner
> - **ETD Calibration** Startup CAS ping-pong measures actual inter-core latency; cross-LLC work stealing tries the empirically-cheapest LLC first, falling back to index order before calibration completes
> - **Dispatch Latency Telemetry** Every task tracks its own scheduling latency (enqueue-to-dispatch) as a per-task EWMA; mean dispatch latency is shown live in the TUI summary bar and clipboard export, or logged periodically in headless mode via `--stats`
> - **Preemption Burst Credit** T1/T2 tasks repeatedly interrupted before completing their quantum earn slice extensions proportional to how many times they were cut short
> - **Desktop-First DVFS** Every tier runs at full CPU clock by default no power-saving throttle on background work since `scx_imperator` targets mains-powered desktops, not laptops or thermally-constrained systems

## Navigation

- [1. Quick Start](#1-quick-start)
- [2. Philosophy](#2-philosophy)
- [3. 4-Tier System](#3-4-tier-system)
- [4. Context Signals](#4-context-signals)
- [5. Profiles](#5-profiles)
- [6. Architecture](#6-architecture)
- [7. Work Stealing & Topology](#7-work-stealing--topology)
- [8. Overhead](#8-overhead)
- [9. Vocabulary](#9-vocabulary)

---

## 1. Quick Start

```bash
# Prerequisites: Linux Kernel 6.12+ with sched_ext, Rust toolchain

# Clone and build
git clone https://github.com/Michael-Sebero/SCX-IMPERATOR
cd SCX-IMPERATOR && cargo build --release

# Install
sudo mv target/release/scx_imperator /bin/
chmod 755 /bin/scx_imperator

# Run (requires root) — uses the Default profile, tuned for desktop gaming
sudo scx_imperator

# Same as above — "gaming" is an accepted alias for the Default profile
sudo scx_imperator -p gaming

# Competitive/esports profile — tightest worst-case latency, more context-switch overhead
sudo scx_imperator -p esports
```

[Full Documentation](https://github.com/Michael-Sebero/SCX-IMPERATOR/blob/main/docs/imperator-documentation.md)

---

## 2. Philosophy

Traditional schedulers (CFS, EEVDF) optimize for **fairness** if a game and a compiler both run, each gets roughly 50% CPU time. For gaming, this creates two problems:

1. **Latency inversion**: A 50µs input handler waits behind a 50ms compile job
2. **Frame jitter**: Game render threads get preempted mid-frame by background work

**scx_imperator's answer**: Classify tasks by *behavior* (how long they actually run), not by type or nice value. Short-burst tasks (input, audio) get instant priority. Long-running tasks (compilers) get larger time slices but lower priority. The system self-tunes no manual tagging or cgroup setup required.

---

## 3. 4-Tier System

Every task is classified into one of four tiers based on its **EWMA** (Exponential Weighted Moving Average) runtime. Classification is automatic and continuous tasks move between tiers as their behavior changes.

### Tier Gates

| Tier | Name | avg_runtime | Examples | Starvation (Default profile) |
| :--- | :--- | :--- | :--- | :--- |
| **T0** | Critical | < 100µs | IRQ handlers, mouse input, audio callbacks | 1.5ms |
| **T1** | Interactive | < 2ms | Compositor, game physics, AI | 8ms |
| **T2** | Frame | < 8ms | Game render threads, video encoding | 20ms |
| **T3** | Bulk | ≥ 8ms | Compilation, background indexing | 100ms |

T0 always runs before T1, which always runs before T2 and so on. This ordering is encoded directly in the dispatch queue sort key no per-dispatch branching to enforce it.

> [!NOTE]
> Starvation ceilings vary by profile — see [§5 Profiles](#5-profiles) for the full table. The values above are the **Default** profile's, which doubles as `--profile gaming`. T0 and T2 are tightened to match **Esports** exactly (1.5ms / 20ms) under the desktop policy that audio/input/render latency shouldn't be sacrificed on a system with CPU headroom to spare; T1 and T3 stay looser to favor smoother frame pacing and fewer context switches under normal play.

> [!TIP]
> **No game task should be in T3.** Game render threads run 2–8ms per frame → T2. Physics/AI run 0.5–2ms → T1. Input handlers run < 100µs → T0. Only tasks doing 8ms+ of uninterrupted CPU work (shader compilation, loading screens) land in T3.

### How Classification Works

1. **Initial placement**: Based on `nice` value `nice < 0` → T0, `nice 0–10` → T1, `nice > 10` → T3. Kthreads at nice 0 start at T1, not T0.
2. **Runtime seeding**: avg_runtime is seeded at the midpoint of the initial tier's expected range, not zero. Starting from zero lets any task with a short first bout masquerade as T0 for several windows.
3. **EWMA authority**: After ~4 bouts, the EWMA avg_runtime becomes authoritative. A nice -5 task that runs 50ms bursts reclassifies to T3 regardless of nice value.
4. **Asymmetric convergence**: Promotions (shorter runtime) converge in ~4 bouts; demotions (longer runtime) take ~16. A game thread that spikes during a level load recovers its T1 priority quickly.
5. **Graduated backoff**: Once a task's tier has been stable for 3 consecutive stops, reclassification slows: T0 rechecks every 1024th stop, T3 every 16th. The EWMA still updates every stop.
6. **Post-sleep recovery**: If a task sleeps for over 500ms, its average is pulled toward the current tier midpoint before the EWMA runs. Prevents a thread that spent a loading screen at T3 from needing 10+ bouts to recover.
7. **Fork inheritance**: Child threads start at half the parent's avg_runtime, in the parent's tier. A newly forked render worker competes at the right tier immediately.
8. **Exec reset**: When a process execs (e.g. a shell launching a game binary), stale classification history is wiped and reseeded from the nice value.

### DRR++ Deficit Tracking

Adapted from network CAKE's flow fairness algorithm:

- Each task starts with a **deficit** (quantum + new-flow bonus ≈ 10ms credit)
- Each execution bout consumes deficit proportional to runtime
- When deficit exhausts → new-flow bonus removed → task competes normally
- This gives newly spawned threads instant responsiveness that naturally decays

---

## 4. Context Signals

These five features fire on top of the base tier system. They don't modify a task's permanent classification — they affect one dispatch or one preemption decision at a time.

### IRQ-Wake Boost

When a wakeup originates from a hardware interrupt, NMI, softirq, or ksoftirqd, the woken task runs at T0 for that one dispatch. The flag is consumed immediately. This matters because a task woken by a mouse click or audio DMA completion may not yet have a T0 EWMA history the hardware urgency shouldn't wait for behavioral evidence to accumulate.

### Waker Tier Inheritance

On wakeup paths, the woken task's tier is compared against the tier of the CPU that woke it (read from a per-CPU mailbox updated on every context switch). If the waker's tier is lower-numbered (higher priority), the wakee is promoted to match it, floored at T1. A T0 audio thread waking a T2 event dispatcher promotes it to T1 for that dispatch.

### Lock-Holder Protection

Tracked via fexit probes on futex acquire/release. When a task holds a contended lock:

1. Its virtual timestamp is advanced within its tier it sorts to the front of same-tier tasks and runs sooner, releasing the lock faster
2. If it exceeds its starvation threshold while holding the lock, preemption is skipped up to 4 consecutive times. After 4 skips or after lock release, normal preemption resumes

The cap of 4 skips bounds the maximum extra latency any waiter can experience to roughly 4ms at default tick rates. Slice expiry (the hard ceiling) is never bypassed.

> [!NOTE]
> **Coverage gaps**: Uncontended locks never enter the kernel and are invisible to this path. `FUTEX_CMP_REQUEUE_PI` (rare, primarily glibc priority-ceiling condition variables) is also not covered the new lock owner won't get the boost until its next explicit futex acquire.

### Dispatch Latency Telemetry

Every task records a timestamp when it enters the dispatch queue (`enqueue_time`) and measures how long it waited before actually running. This per-task dispatch latency is tracked as an α=1/8 EWMA stored in `jitter_ewma_us` — the first per-task scheduling jitter signal in the scheduler.

Each context switch accumulates the current EWMA sample into two per-CPU counters (`nr_jitter_ewma_sum`, `nr_jitter_ewma_count`) in `imperator_stats`. The TUI aggregates these across all CPUs and displays the mean dispatch latency live in the summary bar (`Dispatch latency: Xµs`) and in the clipboard export under `C2-Infra Dispatch latency telemetry`.

Collection itself (`enable_stats`) used to require launching the interactive TUI via `-v`/`--verbose` — a headless deployment (e.g. under systemd) had no way to turn it on and got zero visibility into any of this. `--stats`/`-s` now enables the same collection independently of the TUI: a summary line, including mean dispatch latency, is logged roughly every 60 seconds, and the raw per-CPU counters remain readable via `bpftool map dump` on the scheduler's `bss` map for anyone who wants them directly. `--stats` is implied by `--verbose` and harmless (redundant) alongside it.

The signal resets on exec and fork, and is skipped for tasks dispatched via the SYNC or idle-direct fast paths (which bypass the queue entirely and have no meaningful wait time to record). On pure SYNC workloads the counter stays at zero and the TUI shows `—` rather than a misleading value.

### Preemption Burst Credit

T1 (Interactive) and T2 (Frame) tasks that are preempted before completing their time slice accumulate burst credit. Each preemption adds roughly one quarter of a quantum of credit, up to a per-tier cap:

| Tier | Cap (Default/Esports) | Cap (Sim profile) | Approx. max bonus |
| :--- | :--- | :--- | :--- |
| T0 Critical | none | none | — |
| T1 Interactive | 2000 kns | 2000 kns | ~2ms |
| T2 Frame | 4000 kns | 4000 kns | ~4ms |
| T3 Bulk | none | 1000 kns | Sim only: ~1ms |

The credit is consumed immediately on the same re-enqueue event that earned it, extending the task's slice for that dispatch. A render thread preempted four times in a frame earns proportionally more runway on the next dispatch, reducing the compounding effect of repeated interruptions. Credit is zeroed on tier change, exec, and fork so it never carries across context boundaries.

T0 tasks are excluded on every profile because they are already latency-critical and longer slices work against them. T3 tasks are excluded everywhere **except** the **Sim** profile, where T3 may legitimately be the dominant, most important workload (the simulation/streaming thread itself) rather than disposable bulk work — a sim thread repeatedly preempted by background system tasks earns a small, capped recovery bonus instead of being treated as low-priority background noise.

---

## 5. Profiles

Four profiles are selectable at launch. `gaming` is an accepted alias for `default` — they select the exact same profile, not two separate configurations that happen to match.

| Profile | Base Quantum | T0 Starvation | T2 Starvation | T3 Starvation | T0 Multiplier | T3 Multiplier |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Default** (`gaming`) | 2ms | 1.5ms | 20ms | 100ms | 0.25× | ~4× |
| **Esports** | 1ms | 1.5ms | 20ms | 50ms | 0.25× | ~4× |
| **Sim** | 4ms | 3ms | 80ms | 200ms | 0.25× | ~4× |

**Default** (also reachable as `--profile gaming`) is the scheduler-wide default — `sudo scx_imperator` with no flags runs this profile. It matches **Esports** exactly on T0 and T2 worst-case starvation (1.5ms / 20ms): there's no reason to tolerate slower input/audio or render-thread latency on a desktop with CPU headroom to spare, and 20ms is tight enough to keep a starved render thread under 3 frame-times at 144Hz. Where Default differs from Esports is slice size and T1/T3 ceilings — Default uses double the base quantum and a double-length T3 starvation window, trading a larger worst-case margin for fewer context switches under normal, uncontended play. Combined with full-clock DVFS on every tier and lock-holder priority boosting for Wine/Proton, this profile requires no additional configuration on a desktop PC.

**Esports** tightens slice size and T3 starvation further than Default, at the cost of more context-switch overhead — use it when minimum worst-case latency matters more than raw throughput (e.g. a dedicated competitive-play machine). It is not strictly tighter than Default on every axis: T0/T2 ceilings are now tied between the two profiles.

**Sim** is designed for strategy, 4X, city-builder, and open-world games where a simulation or streaming thread is the dominant workload. It uses a 4ms quantum (reduces context-switch fragmentation on sustained T2/T3 work), looser T2/T3 starvation thresholds (nothing latency-critical is competing with the sim thread), and enables T3 burst credit — a simulation thread repeatedly preempted by background system work earns proportional slice extensions. T1 starvation matches Default exactly (8ms); T0 is proportionally — not literally — as protected as Default's, scaled to Sim's longer base quantum (3ms starvation over a 1ms T0 slice is the same 3× safety margin as Default's 1.5ms over 0.5ms).

> [!NOTE]
> **Sim vs Default on FPS titles:** Sim's looser T2/T3 starvation thresholds mean background and render-adjacent tasks take longer to get preempted. On a pure FPS workload this is harmless — background tasks in a gaming session rarely saturate any core — but the safe choice for competitive play remains **Esports** or **Default**.

The `--starvation` flag scales all tier thresholds proportionally from the T3 base, preserving inter-tier ratios.

### DVFS Policy

Every tier on every profile runs at `SCX_CPUPERF_ONE` (100% of hardware-permitted clock) no frequency throttle is applied to background (T3) work the way earlier revisions did. `scx_imperator` targets desktop PCs on mains power; a laptop-style trade of CPU clock for battery or thermal headroom doesn't apply, and a throttled T3 task simply takes longer to finish a shader compile or background install for no benefit when the GPU is the actual bottleneck (the common case in nearly every game). The mechanism that bounds T3's worst-case impact on foreground work is starvation preemption (the table above), not frequency throttling.

---

## 6. Architecture

### Scheduler Flow

```
select_cpu
  ├── IRQ context?      → stamp CAKE_FLOW_IRQ_WAKE on tctx
  ├── SCX_WAKE_SYNC?    → direct dispatch to waker's CPU (dispatch_sync_cold)
  ├── Idle CPU found?   → direct dispatch via SCX_DSQ_LOCAL_ON
  └── All busy          → tunnel (LLC, timestamp) to enqueue, return prev_cpu

enqueue
  ├── stamp enqueue_time for dispatch latency measurement
  ├── sleep_entry_time set?  → pull avg_runtime toward tier midpoint if slept >500ms (post-sleep recovery)
  ├── SCX_ENQ_PREEMPT + T1/T2? → accumulate burst_credit (up to per-tier cap)
  ├── burst_credit > 0? → extend slice by credit amount, zero credit
  ├── IRQ_WAKE flag     → tier = T0 (one-shot, consumed here)
  ├── Waker mailbox     → promote wakee tier if waker is higher priority
  ├── Lock-holder flag  → advance virtual timestamp within tier
  ├── vtime = (tier << 56) | timestamp
  ├── insert into per-LLC DSQ
  └── T0/T1: kick T3 (or T2) victim in same LLC via bitmask

dispatch
  ├── pull from local LLC DSQ
  └── if empty: ETD-ordered steal from other LLCs

running   → stamp last_run_at, update jitter_ewma_us from enqueue_time, consume enqueue_time,
            publish tier to per-CPU mailbox, set tier bitmask
tick      → slice expiry check, starvation check, lock-holder skip, DVFS update
stopping  → clear tier bitmask (before reclassify), run EWMA + DRR++
reclassify→ if tier changed: recompute next_slice, zero burst_credit
```

### Key Data Structures

| Structure | Size | Purpose |
| :--- | :--- | :--- |
| `imperator_task_ctx` | 64B (1 cache line) | Per-task EWMA state, tier, deficit, lock flags, dispatch latency EWMA, burst credit |
| `mega_mailbox_entry` | 64B (1 cache line) | Per-CPU tier broadcast for waker inheritance |
| `imperator_stats` | variable | Aggregated scheduler counters including burst credit earning and consumption rates |

### `imperator_task_ctx` Layout

| Bytes | Field | Purpose |
| :--- | :--- | :--- |
| 0–7 | `next_slice` | Time slice for next dispatch |
| 8–15 | `deficit_avg_fused` / `packed_info` | DRR++ deficit, avg_runtime, tier, flags |
| 16–19 | `last_run_at` | Timestamp of last dispatch start |
| 20–21 | `reclass_counter` | Graduated backoff counter |
| 22 | `overrun_count` | 8-bit shift register of per-bout overrun history |
| 23 | `lock_skip_count` | Consecutive starvation skips while holding a lock |
| 24 | `pending_futex_op` | Futex op recorded at syscall entry for cross-CPU exit matching |
| 25–27 | `__align_pad` | Explicit alignment gap before u32 field |
| 28–31 | `enqueue_time` | Wall-clock ns at queue entry; consumed after one use |
| 32–33 | `jitter_ewma_us` | Per-task dispatch latency EWMA in ~µs |
| 34–35 | `burst_credit` | Accumulated preemption-recovery credit in kns units |
| 36–63 | `__pad` | Reserved |

---

## 7. Work Stealing & Topology

### ETD Calibration

On startup, two threads are pinned to each CPU pair and exchange a flag with atomic CAS to measure actual inter-core latency. This runs in the background and takes a few seconds. Until it completes, cross-LLC stealing falls back to index order.

| Parameter | Value |
| :--- | :--- |
| Round-trips per sample | 500 |
| Samples per pair | 50 |
| Warmup iterations | 200 |
| Max acceptable σ | 15 ns (3 retries) |

The **median** of samples is used (not the mean) to filter IRQ jitter. If affinity pinning fails for a pair, that entry is filled with a 500 ns sentinel so it is never treated as a free path.

### Dispatch Order

Each LLC has its own dispatch queue. On a task dispatch:

1. Try the calling CPU's local LLC first covers most dispatches with zero cross-LLC traffic
2. If empty, build a steal mask of non-empty LLCs and try the lowest-ETD-cost one first
3. Fall through remaining LLCs in order

On single-LLC systems the steal path is eliminated entirely at JIT load time.

### Preemption Kick

When a T0 or T1 task is enqueued into a full LLC, a victim CPU in the same LLC is kicked immediately. Victim preference is T3 (bulk) first, T2 (frame) as fallback. T0 and T1 CPUs are never kicked to run another latency-critical task.

---

## 8. Overhead

> [!NOTE]
> The figures below were measured against an earlier revision and have not been re-profiled since. Several features added later in this scheduler's history (ETD-aware steal ordering, the M-2 mailbox-consistency fix, the live `tier_configs`-coupled burst-credit ceiling, the post-sleep recovery check moving from `stopping` to `enqueue`) touch the functions listed here; their cost is believed small but is not reflected in the numbers below. Treat this table as directionally useful, not as a current measurement.

The added cost relative to a minimal sched_ext skeleton is approximately 20%, concentrated in `select_cpu` and `enqueue`. The cycle counts below predate the ETD-aware steal-ordering feature in `dispatch` (see [§7](#7-work-stealing--topology)) and have not been re-measured since; treat the `dispatch` row as **not current** rather than as a measured zero.

| Function | Added cost | Notes |
| :--- | :--- | :--- |
| `select_cpu` | ~2 cycles | Storage skipped on all-busy non-IRQ non-SYNC path |
| `enqueue` | +6 cycles steady-state; +19 cycles T1/T2 preempt | Mailbox read is the baseline cost; burst credit accumulation and consumption add ~13 cycles on the preemption path only |
| `dispatch` | *unmeasured since ETD-steal was added* | Local-LLC-empty path now computes a cheapest-cost candidate across LLCs before falling back to index order; local-LLC-hit path (the common case) is believed unaffected but has not been re-profiled |
| `tick` | +2 cycles | Lock-holder check, inside starvation branch only |
| `running` | +11 cycles | Mailbox write + tier bitmask set + jitter EWMA update (SYNC/idle path: +2 cycles — guard branch only) |
| `stopping` | +5 cycles | Tier bitmask clear |
| `lock_bpf` probes | ~50 ns | Only on contended lock operations |

All new fields (`enqueue_time`, `jitter_ewma_us`, `burst_credit`) sit on the same 64B cache line as `last_run_at` and `next_slice`. No additional cache misses are introduced on any path.

---

## 9. Vocabulary

### Core Concepts

| Term | Definition |
| :--- | :--- |
| **EWMA** | Exponential Weighted Moving Average. Tracks task runtime with asymmetric decay promotions converge in ~4 bouts, demotions in ~16. |
| **Tier** | Classification level (T0–T3) by avg_runtime. Controls slice size, starvation window, vtime priority and DVFS target. |
| **Deficit** | Per-task credit from DRR++. New tasks get bonus credit; exhaustion removes the bonus and the task competes normally. |
| **Quantum** | Base time slice allotted before a scheduling decision. Scaled by tier multiplier. |
| **Starvation** | Maximum time a task can wait without running before preemption is forced, regardless of tier ordering. |
| **DRR++** | Deficit Round Robin++. Network CAKE flow-fairness algorithm adapted for CPU task scheduling. |
| **Jitter** | Variance in scheduling latency between consecutive events. Low jitter = consistent frame delivery. |
| **Dispatch Latency** | Time between a task entering the dispatch queue and actually running. Tracked per-task as `jitter_ewma_us`; mean shown live in TUI summary bar. |
| **Burst Credit** | Per-task slice extension credit earned by T1/T2 tasks on each preemption (T3 too, Sim profile only), consumed on the next dispatch. Bounds: T1 ≈ 2ms, T2 ≈ 4ms, T3 ≈ 1ms (Sim only). Zeroed on tier change, exec, and fork. |
| **kns** | Kilonanoseconds — nanoseconds divided by 1024 (right-shift by 10). Internal unit used for deficit and burst credit to keep values in u16 range. |

### Architecture

| Term | Definition |
| :--- | :--- |
| **Fused Config** | 3 parameters packed into one 64-bit word: `[mult:12][quantum:16][starve:20]`, with 16 bits reserved. A `budget` field previously occupied bits 28–43 but was never read by any scheduling decision; it was removed and `starve` repacked down into the freed range rather than leaving a gap. |
| **Mega-Mailbox** | 64B per-CPU cache-line-isolated state. Carries tier information for waker inheritance with zero false sharing. |
| **Graduated Backoff** | Confidence system that reduces reclassification frequency once a task's tier has been stable for 3+ stops. |
| **Vtime** | Virtual timestamp used as the DSQ sort key: `(tier << 56) | timestamp`. Encodes both priority and arrival order. |
| **Bit-History Register** | 8-bit shift register tracking per-bout overrun outcomes. Demotion triggers when 4 of 8 recent bouts exceeded the tier gate. |

### Hardware

| Term | Definition |
| :--- | :--- |
| **CCD** | Core Complex Die. Physical chiplet containing cores (e.g. 9800X3D: 1 CCD, 9950X: 2 CCDs). |
| **LLC** | Last Level Cache (L3). Cores in the same LLC communicate ~3–5× faster than cross-LLC. |
| **SMT** | Simultaneous Multi-Threading. Two logical CPUs per physical core. |
| **P/E Cores** | Intel hybrid architecture: Performance cores (fast) and Efficiency cores (power-saving). |
| **ETD** | Empirical Topology Discovery. Measures inter-core CAS latency at startup to guide work stealing. |
| **Cache Line** | 64-byte block of memory. The smallest unit the CPU loads from RAM. Foundation of all data layout decisions. |

### Research Sources

| Feature | Derived from |
| :--- | :--- |
| DRR++ tier queuing | Network [CAKE](https://www.bufferbloat.net/projects/codel/wiki/Cake/) queueing discipline |
| EWMA classification, per-LLC DSQ | scx_cake |
| Asymmetric EWMA, graduated backoff, ETD calibration | scx_cake |
| IRQ-source wakeup detection | scx_lavd (`lavd_select_cpu`) |
| Waker tier inheritance | scx_lavd (`lat_cri_waker/wakee`) |
| Lock-holder detection and starvation skip | scx_lavd (`lock.bpf.c`) |
| Dispatch latency telemetry (`jitter_ewma_us`) | Original — closes the per-task jitter measurement gap |
| Preemption burst credit (DRR++ extension) | Original — leaky-bucket burst allowance applied to CPU time-slice management |
| ETD-aware steal ordering (cheapest-LLC-first) | Original — extends ETD calibration from a fallback-avoidance signal into an active steal-ordering input |
| Desktop-first DVFS policy (no T3 throttle, starvation-bounded instead) | Original — replaces frequency throttling with starvation preemption as the mechanism bounding background-task impact |
