## **I.M.P.E.R.A.T.O.R**

**Integrated · Multitiered · Priority · Execution · Ranked · Adaptive · Topology · Ordered · Runtime**

> **ABSTRACT**: `scx_imperator` is a BPF CPU scheduler built on [sched_ext](https://github.com/sched-ext/scx), designed for **gaming workloads** on modern AMD and Intel hardware. It classifies every task by observed runtime behavior and routes work through a 4-tier priority system high-priority tasks like audio callbacks and mouse input get CPU time first, bulk work like compilers gets it last.
>
> - **4-Tier Classification** Tasks sorted by asymmetric EWMA avg_runtime into Critical / Interactive / Frame / Bulk
> - **IRQ-Wake Boosting** Hardware wakeups (GPU vsync, audio DMA, network) immediately promote that task to T0 for one dispatch
> - **Waker Tier Inheritance** High-priority task waking a lower-priority one lifts the wakee's tier, keeping producer-consumer chains tight
> - **Lock-Holder Protection** Futex holders get scheduling priority and starvation skips to release locks faster, unblocking waiters sooner
> - **ETD Calibration** Startup CAS ping-pong measures actual inter-core latency; work stealing always prefers the cheapest path

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

# Run (requires root)
sudo scx_imperator

# Competitive/esports profile
sudo scx_imperator -p esports

# Legacy profile (more throughput-friendly)
sudo scx_imperator -p legacy
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

| Tier | Name | avg_runtime | Examples | Starvation |
| :--- | :--- | :--- | :--- | :--- |
| **T0** | Critical | < 100µs | IRQ handlers, mouse input, audio callbacks | 3ms |
| **T1** | Interactive | < 2ms | Compositor, game physics, AI | 8ms |
| **T2** | Frame | < 8ms | Game render threads, video encoding | 40ms |
| **T3** | Bulk | ≥ 8ms | Compilation, background indexing | 100ms |

T0 always runs before T1, which always runs before T2 and so on. This ordering is encoded directly in the dispatch queue sort key no per-dispatch branching to enforce it.

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

These three features fire on top of the base tier system. They don't modify a task's permanent classification they affect one dispatch or one preemption decision at a time.

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

---

## 5. Profiles

Three profiles are selectable at launch. `Default` is identical to `Gaming`.

| Profile | Base Quantum | T3 New-Flow Bonus | T3 Starvation | T0 Multiplier | T3 Multiplier |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Gaming** | 2ms | 8ms | 100ms | 0.5× | ~4× |
| **Esports** | 1ms | 4ms | 50ms | 0.25× | ~4× |
| **Legacy** | 4ms | 12ms | 200ms | 0.75× | 2× |

**Gaming** works well for most desktops. **Esports** tightens everything shorter slices, half the starvation windows, lower T0 multiplier use it for minimum latency above all else. **Legacy** leans toward fairness; background work completes at a more reasonable pace.

The `--starvation` flag scales all tier thresholds proportionally from the T3 base, preserving inter-tier ratios.

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
  ├── IRQ_WAKE flag     → tier = T0 (one-shot, consumed here)
  ├── Waker mailbox     → promote wakee tier if waker is higher priority
  ├── Lock-holder flag  → advance virtual timestamp within tier
  ├── vtime = (tier << 56) | timestamp
  ├── insert into per-LLC DSQ
  └── T0/T1: kick T3 (or T2) victim in same LLC via bitmask

dispatch
  ├── pull from local LLC DSQ
  └── if empty: ETD-ordered steal from other LLCs

running   → stamp last_run_at, publish tier to per-CPU mailbox, set tier bitmask
tick      → slice expiry check, starvation check, lock-holder skip, DVFS update
stopping  → clear tier bitmask (before reclassify), run EWMA + DRR++
```

### Key Data Structures

| Structure | Size | Purpose |
| :--- | :--- | :--- |
| `imperator_task_ctx` | 64B (1 cache line) | Per-task EWMA state, tier, deficit, lock flags |
| `mega_mailbox_entry` | 64B (1 cache line) | Per-CPU tier broadcast for waker inheritance |
| `imperator_stats` | 64B (1 cache line) | Aggregated scheduler counters |

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

The added cost relative to a minimal sched_ext skeleton is approximately 20%, concentrated in `select_cpu` and `enqueue`. The `dispatch` path the tightest loop under sustained gaming load is unchanged.

| Function | Added cost | Notes |
| :--- | :--- | :--- |
| `select_cpu` | ~2 cycles | Storage skipped on all-busy non-IRQ non-SYNC path |
| `enqueue` | +6 cycles steady-state | Mailbox read (waker inheritance) is the main cost |
| `dispatch` | 0 | Unchanged |
| `tick` | +2 cycles | Lock-holder check, inside starvation branch only |
| `running` | +7 cycles | Mailbox write + tier bitmask set |
| `stopping` | +5 cycles | Tier bitmask clear |
| `lock_bpf` probes | ~50 ns | Only on contended lock operations |

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

### Architecture

| Term | Definition |
| :--- | :--- |
| **Fused Config** | 4 parameters packed into one 64-bit word: `[mult:12][quantum:16][budget:16][starve:20]`. |
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
