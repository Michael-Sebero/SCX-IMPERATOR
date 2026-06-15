# scx_imperator

A gaming-focused CPU scheduler built on [sched_ext](https://github.com/sched-ext/scx). It classifies tasks by how long they actually run and routes them through a 4-tier priority system. High-priority work like audio callbacks and mouse input gets CPU time first, bulk work like compilers gets it last.

The three things that make it different from a generic SCX scheduler:

* **IRQ-wake boosting** when hardware (GPU vsync, audio DMA, network) wakes a task, that task runs at max priority for that one dispatch regardless of its history
* **Waker inheritance** a high-priority task waking a lower-priority one temporarily lifts the wakee's priority, keeping producer-consumer chains tight
* **Lock-holder protection** tasks holding a futex get a scheduling advantage and starvation protection so they release the lock faster, unblocking waiters sooner

---

## The Tier System

Tasks are classified into four tiers based on a rolling average of how long they run. Classification happens automatically no manual tagging or cgroup setup.

| Tier | Name | Runtime | Examples |
| :--- | :--- | :--- | :--- |
| T0 | Critical | < 100µs | IRQ handlers, mouse input, audio callbacks |
| T1 | Interactive | < 2ms | Compositor, physics, AI |
| T2 | Frame | < 8ms | Game render threads, encoding |
| T3 | Bulk | ≥ 8ms | Compilation, background indexing |

T0 always runs before T1, which always runs before T2, and so on. This ordering is encoded directly in the dispatch queue's sort key so there's no per-dispatch branching to enforce it.

The classification uses an asymmetric EWMA promotions (shorter runtime) converge in ~4 bouts, demotions (longer runtime) take ~16. A game thread that spikes during a level load recovers its T1 priority quickly rather than sitting misclassified for 16 scheduling windows.

A few things that keep classification stable:

* **Graduated backoff** once a task's tier has been stable for 3 stops, the full reclassification path runs less often (T0: every 1024th stop, T3: every 16th). The EWMA still updates every stop.
* **Post-sleep recovery** if a task sleeps for over 500ms, its average is pulled toward the current tier midpoint before the EWMA runs. Prevents a game thread that spent a loading screen at T3 from needing 10+ bouts to recover.
* **Fork inheritance** child threads start at half the parent's average runtime, in the parent's tier. A newly forked render worker competes at the right tier immediately.
* **Exec reset** when a process execs (e.g. a shell launching a game binary), stale classification history is wiped and reseeded from the nice value.

---

## Profiles

Three profiles, selectable at launch. `Default` is identical to `Gaming`.

| Profile | Base Quantum | T3 New-Flow Bonus | T3 Starvation | T0 Multiplier | T3 Multiplier |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Gaming** | 2ms | 8ms | 100ms | 0.5× | ~4× |
| **Esports** | 1ms | 4ms | 50ms | 0.25× | ~4× |
| **Legacy** | 4ms | 12ms | 200ms | 0.75× | 2× |

**Gaming** is the default and works well for most desktops. **Esports** tightens everything shorter slices, half the starvation windows, lower T0 multiplier. Use it if you're running a tournament machine or want minimum latency above all else. **Legacy** leans more toward fairness and is there if you need background work to complete at a reasonable pace.

The `--starvation` flag scales all tier thresholds proportionally from the T3 base, preserving inter-tier ratios.

---

## Context Signals

These three features fire on top of the base tier system. They don't modify a task's permanent classification they affect one dispatch or one preemption decision at a time.

### IRQ-wake boost

When a wakeup originates from a hardware interrupt, NMI, softirq, or ksoftirqd, the woken task runs at T0 for that one dispatch. The flag is consumed and gone. This matters because a task woken by a mouse click or audio DMA completion may not yet have a T0 EWMA history it might be new, or freshly exec'd. The hardware urgency shouldn't wait for behavioral evidence to accumulate.

### Waker tier inheritance

On wakeup paths, the woken task's tier is compared against the tier of the CPU that woke it (read from a per-CPU mailbox updated on every context switch). If the waker's tier is lower (higher priority), the wakee is promoted to match it, floored at T1. So a T0 audio thread waking a T2 event dispatcher promotes it to T1 for that dispatch. The T1 floor prevents the IRQ-wake path from being the only legitimate way to reach T0.

### Lock-holder protection

Tracked via fexit probes on futex acquire/release. When a task holds a contended lock, two things happen:

1. Its virtual timestamp is advanced within its tier it sorts to the front of same-tier tasks and runs sooner, releasing the lock faster
2. If it exceeds its starvation threshold while holding the lock, preemption is skipped up to 4 consecutive times. After 4 skips or after the lock is released, normal preemption resumes

The cap of 4 skips bounds the maximum extra latency any waiter can experience to roughly 4ms at default tick rates. Slice expiry (the hard ceiling) is never bypassed.

Coverage gaps: uncontended locks never enter the kernel so they're invisible to this path. `FUTEX_CMP_REQUEUE_PI` (rare, primarily glibc priority-ceiling condition variables) also isn't covered the new lock owner won't get the boost until its next explicit futex acquire.

---

## Work Stealing and Topology

### ETD calibration

On startup, two threads are pinned to each CPU pair and exchange a flag with atomic CAS to measure actual inter-core latency. This runs in the background and takes a few seconds. Until it completes, cross-LLC stealing falls back to index order.

| Parameter | Value |
| :--- | :--- |
| Round-trips per sample | 500 |
| Samples per pair | 50 |
| Warmup iterations | 200 |
| Max acceptable σ | 15 ns (3 retries) |

The median of samples is used (not the mean) to filter IRQ jitter. If affinity pinning fails for a pair, that pair's entry is filled with a 500 ns sentinel so it's never treated as a free path.

### Dispatch order

Each LLC has its own dispatch queue. On a task dispatch:

1. Try the calling CPU's local LLC first covers most dispatches with zero cross-LLC traffic
2. If empty, build a steal mask of non-empty LLCs and try the lowest-ETD-cost one first
3. Fall through remaining LLCs in order

On single-LLC systems the steal path is eliminated entirely at JIT load time.

### Preemption kick

When a T0 or T1 task is enqueued into a full LLC, a victim CPU in the same LLC is kicked immediately. Victim preference is T3 (bulk) first, T2 (frame) as fallback. T0 and T1 CPUs are never kicked to run another latency-critical task.

---

## Initial Classification

Before any EWMA data exists, tasks start from two signals:

* **Nice value:** nice < 0 → T0, nice > 10 → T3, otherwise → T1
* **Kthreads at nice 0:** start at T1, not T0 `kcompactd`, `kswapd` and similar shouldn't start at max priority

Average runtime is seeded at the midpoint of the initial tier's expected range rather than zero. Starting from zero let any task with a short first bout masquerade as T0 for several scheduling windows.

---

## Scheduler Architecture

```
select_cpu
  ├── IRQ context? → stamp CAKE_FLOW_IRQ_WAKE on tctx
  ├── SCX_WAKE_SYNC? → direct dispatch to waker's CPU (dispatch_sync_cold)
  ├── Idle CPU found? → direct dispatch via SCX_DSQ_LOCAL_ON
  └── All busy → tunnel (LLC, timestamp) to enqueue, return prev_cpu

enqueue
  ├── Feature 1: IRQ_WAKE flag → tier = T0 (one-shot, consumed here)
  ├── Feature 2: waker mailbox read → promote wakee tier if waker is higher
  ├── Feature 3: lock-holder flag → advance virtual timestamp within tier
  ├── vtime = (tier << 56) | timestamp
  ├── insert into per-LLC DSQ
  └── T0/T1: kick T3 (or T2) victim in same LLC via bitmask

dispatch
  ├── pull from local LLC DSQ
  └── if empty: ETD-ordered steal from other LLCs

running  → stamp last_run_at, publish tier to per-CPU mailbox, set tier bitmask
tick     → slice expiry check, starvation check, lock-holder skip, DVFS update
stopping → clear tier bitmask (before reclassify), run EWMA + DRR++
```

---

## Overhead

The added cost relative to a minimal sched_ext skeleton is approximately 20%, concentrated in `select_cpu` and `enqueue`. The `dispatch` path the tightest loop under sustained gaming load is unchanged.

| Function | Added cost | Notes |
| :--- | :--- | :--- |
| `select_cpu` | ~2c on dominant path | Storage skipped on all-busy non-IRQ non-SYNC path |
| `enqueue` | +6c steady-state | Mailbox read (Feature 2) is the main cost |
| `dispatch` | 0 | Unchanged |
| `tick` | +2c | Lock-holder check, inside starvation branch only |
| `running` | +7c | Mailbox write + tier bitmask set |
| `stopping` | +5c | Tier bitmask clear |
| `lock_bpf` probes | ~50ns | Only on contended lock operations |

---

## Research Sources

| Feature | Derived from |
| :--- | :--- |
| DRR++ tier queuing | Network CAKE queueing discipline |
| EWMA classification + per-LLC DSQ | scx_cake (CAKE original) |
| Asymmetric EWMA, graduated backoff, ETD calibration | scx_cake (CAKE original) |
| IRQ-source wakeup detection | scx_lavd (`lavd_select_cpu`) |
| Waker tier inheritance | scx_lavd (`lat_cri_waker/wakee`) |
| Lock-holder detection and starvation skip | scx_lavd (`lock.bpf.c`) |
