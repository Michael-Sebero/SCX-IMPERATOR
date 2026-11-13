# scx_imperator

A gaming-focused CPU scheduler built on [sched_ext](https://github.com/sched-ext/scx). It classifies tasks by how much CPU they use between sleeps and routes them through a 4-tier priority system. High-priority work like audio callbacks and mouse input gets CPU time first, bulk work like compilers gets it last.

The three things that make it different from a generic SCX scheduler:

* **IRQ-wake boosting** when hardware (GPU vsync, audio DMA, network) or a timer wakes a task while every CPU is busy, that task is queued at max priority for that one dispatch regardless of its history (bulk tasks one tier below that)
* **Waker inheritance** a high-priority task waking a lower-priority one temporarily lifts the wakee's priority, keeping producer-consumer chains tight
* **Deadline-bounded tiers** tasks that arrive together run in strict tier order, but every tier has a budget, so a lower-tier task that has waited long enough goes ahead of newer higher-tier work instead of starving

* **Lock-holder protection** a task that just acquired a futex-based lock is not preempted for a short window and is re-queued slightly ahead of its tier if switched out while holding it

Gen 6 (see the [README](../README.md#12-gen-6-changes)) made the IRQ-wake boost and lock-holder protection actually run; both were dead code before.

---

## The Tier System

Tasks are classified into four tiers based on a rolling average of their burst length: the CPU time a task uses between waking and sleeping. Classification happens automatically no manual tagging or cgroup setup.

| Tier | Name | Runtime | Examples |
| :--- | :--- | :--- | :--- |
| T0 | Critical | < 100µs | IRQ handlers, mouse input, audio callbacks |
| T1 | Interactive | < 2ms | Compositor, physics, AI |
| T2 | Frame | < 8ms | Game render threads, encoding |
| T3 | Bulk | ≥ 8ms | Compilation, background indexing |

### Queue order

Each LLC has one dispatch queue sorted by a single key, the task's deadline: `enqueue time + tier budget`. Budgets rise with tier in every profile, so tasks that arrive together run T0, then T1, then T2, then T3, with no per-dispatch branching to enforce it. A waiting task stops being passed by newer higher-tier work once it has waited the gap between the two budgets. On the Default profile that is 6.5ms for T1 behind T0, 12ms for T2 behind T1and 80ms for T3 behind T2.

Up to Gen 4 the sort key was `(tier << 56) | timestamp`, which is strict priority with no aging: a queued T3 task could wait behind T0 to T2 work until the sched_ext watchdog (30 s default) disabled the scheduler.

### Classification

The classification uses an asymmetric EWMA: promotions (shorter runtime) converge in ~4 samples, demotions (longer runtime) take ~16. A game thread that spikes during a level load recovers its T1 priority quickly rather than sitting misclassified for 16 scheduling windows.

Each sample is a burst: CPU time summed from the moment the task wakes until it sleeps, across any preemptions in between. While a burst is still in progress, the running total can only raise the average; promotion waits until the task actually sleeps. A sleep means the task left `TASK_RUNNING`; up to Gen 5 a property-change dequeue (affinity, nice, cgroup) also counted, which kept pure CPU spinners in T2. Up to Gen 4 each preempted bout was sampled on its own. A preempted bout ends at the scheduler's own slice boundary, so under contention every CPU-bound task drifted to T2and a render thread flipped between T1 and T2 depending on where its burst was cut.

A few things that keep classification stable:

* **Hysteresis** promotion requires the average to fall below 90% of the tier gate (90µs / 1800µs / 7200µs).
* **Overrun demotion** on each full reclassification pass, an 8-bit shift register records whether the sample exceeded 1.5× the tier gate (150µs / 3ms / 12ms). When 4 of the last 8 recorded samples did, the task drops one tier. An average above 24ms with a stable tier forces T3.
* **Graduated backoff** once a task's tier has been stable for 3 stops, the full reclassification path runs less often (T0: every 1024th stop, T1: every 128th, T2: every 32nd, T3: every 16th). The EWMA still updates every stop.
* **Frame-cadence cap** a task whose sleep-to-sleep period averages 34ms or less (30 fps or faster) and that is idle for at least 1/8 of each period is held at T2 instead of T3. A game main thread running 10ms of a 16.6ms frame stays T2; compilers and saturated workers still reach T3. From LAVD's `wait_freq` signal.
* **Post-sleep recovery** when a task wakes after sleeping over 500ms and is queued because no CPU is idle, its average moves halfway toward the midpoint of its current tier (50µs / 1050µs / 5000µs / 8001µs). Prevents a game thread that spent a loading screen at T3 from needing 10+ bursts to recover. Wakeups placed directly on an idle CPU skip this step.

Forked threads are seeded from their own nice value like any other new task, and classification carries across `exec` (sched_ext has no exec hook). The fork-inheritance and exec-reset code that never ran (task storage did not exist yet in `init_task`) was removed in Gen 6.

---

## Profiles

Three profiles, selectable at launch with `-p`. `gaming` is an accepted alias for `default`.

| Profile | Base Quantum | New-Flow Bonus | Budgets T0 / T1 / T2 / T3 | Slices T0 / T1 / T2 / T3 |
| :--- | :--- | :--- | :--- | :--- |
| **Default** (`gaming`) | 2ms | 8ms | 1.5 / 8 / 20 / 100ms | 0.5 / 2 / 4 / 8ms |
| **Esports** | 1ms | 4ms | 1.5 / 4 / 20 / 50ms | 0.25 / 1 / 2 / 4ms |
| **Sim** | 4ms | 8ms | 3 / 8 / 80 / 200ms | 1 / 4 / 8 / 16ms |

Tier multipliers are the same on every profile: T0 0.25×, T1 1×, T2 2×, T3 ~4× (4095/1024). A task re-queued without a wakeup (slice expiry, kick, yield) gets one base quantum, or its tier slice if shorter.

**Default** is the desktop gaming profile and needs no other flags. **Esports** halves the quantum and tightens the T1 and T3 budgets for minimum worst-case latency, at the cost of more context switches. **Sim** is for strategy, 4Xand open-world games whose simulation or streaming thread dominates: a 4ms quantum and larger T2 and T3 budgets.

The `--starvation` flag scales all tier budgets proportionally from the T3 base, preserving inter-tier ratios and therefore the tier order. `--quantum` and `--new-flow-bonus` override the profile's values, in µs. `--lock-boost off` and `--no-irq-boost` switch the two context boosts off for A/B comparisons.

Up to Gen 4 the BPF side read compile-time copies of the quantum (2ms) and new-flow bonus (8ms), so Esports, Simand both override flags had no effect on slices or the bonus.

---

## Context Signals

These features act on top of the base tier system. They don't modify a task's permanent classification; they affect one dispatch or one queue position at a time. None of them can lift a T3 (bulk) task above T2, so bulk work never gains a tier that triggers a preemption kick.

### IRQ-wake boost

When a wakeup originates from a hardware interrupt, NMI, softirq, or ksoftirqd and every CPU is busy, the woken task is queued at T0 for that one dispatch (a T3 task at T2). The flag is consumed and gone, and the task keeps its own slice. A task woken by a mouse click or audio DMA completion may not yet have a T0 EWMA history; the hardware urgency shouldn't wait for behavioral evidence to accumulate. Wakeups placed directly on an idle CPU are not boosted, since they run immediately anyway.

Timer expirations count as interrupts. On non-PREEMPT_RT kernels, hrtimer sleepers (nanosleep, futex, poll and epoll timeouts) expire in hardirq context, so a task waking from a timed sleep is boosted too. That covers sleep-based frame limiters and also any background task that wakes on a timer.

Interrupt context is read from the per-CPU preempt count, as LAVD does. Up to Gen 5 the checks were declared as weak kfuncs that no kernel exports, so only ksoftirqd wakeups were ever boosted. `--no-irq-boost` disables the boost.

### Waker tier inheritance

On queued wakeups, the woken task's tier is compared against the tier of the CPU that woke it (read from a per-CPU mailbox updated on every context switch). If the waker's tier is lower (higher priority), the wakee is promoted to match it, floored at T1 (T2 for a T3 wakee). So a T0 audio thread waking a T2 event dispatcher promotes it to T1 for that dispatch. The promotion changes queue order and kick eligibility; the slice stays the wakee's own.

On 6.15+ kernels a wakeup's `ops.enqueue` runs on the waker's CPU, so the mailbox read is the waker's tier. On 6.12 to 6.14, wakeups delivered through the ttwu wakelist run `ops.enqueue` on the target CPU and read that CPU's mailbox instead.

### Lock-holder protection

From LAVD's futex boost. A task is a lock holder from the moment `futex_wait`, `futex_waitv` (Proton's fsync), `futex_wait_requeue_pi` or `futex_lock_pi` returns a wake or acquire, until it calls `futex_wake`, `futex_wake_op` or `futex_unlock_pi`, or stops running. For a quarter quantum after the acquire (0.5ms on Default) its CPU is not chosen as a preemption victim, and when its slice runs out it is kept running once for that same window. If it is switched out still holding the flag, its re-queue gets the within-tier deadline advance once.

The window exists because `futex_wait` returning 0 means "woken", which is also what condvar and job-queue waiters see. Probes are fexit programs on the futex functions, with syscall tracepoints as a fallback (`--lock-boost auto|fexit|tracepoint|off`). Up to Gen 5 `lock.bpf.c` was not compiled into the scheduler at all.

Coverage gaps: uncontended locks never enter the kernel, so they are invisible to this path. `FUTEX_WAIT_REQUEUE_PI` is covered at the waiter's own syscall return, which can lag the ownership transfer during the waker's requeue call by up to one scheduling round-trip.

### Dispatch latency telemetry

Every queued wakeup measures how long the task waited between entering the dispatch queue and running, tracked as a per-task α=1/8 EWMA (`jitter_ewma_us`). Collection (`enable_stats`) is switched on by `-s`/`--stats`, which logs a summary roughly every 60 seconds, or by the TUI (`-v`/`--verbose`). Tasks placed directly on an idle CPU never enter the queue and aren't sampled.

The sched_ext debug dump (SysRq-D) includes a per-task line with tier, average and current burst, sleep cadence, deficit and flags.

---

## Work Stealing and Topology

### ETD calibration

On startup, two threads are pinned to a CPU pair and exchange a flag with atomic CAS to measure actual inter-core latency, under SCHED_FIFO priority 99. This runs in the background and takes a few seconds. By default only 3 evenly spread CPU pairs per LLC pair are measured; `--full-etd-sweep` measures every pair. Calibration is skipped entirely on single-LLC systems. With exactly two LLCs the steal scan has a single candidate, so the cost table only changes decisions on three or more LLCs. Until calibration completes, cross-LLC stealing falls back to index order.

| Parameter | Value |
| :--- | :--- |
| Round-trips per sample | 500 |
| Samples per pair | 50 |
| Warmup iterations | 200 |
| Max acceptable σ | 15 ns (3 retries) |

The median of samples is used (not the mean) to filter IRQ jitter. If affinity pinning fails for a pair, that pair's entry is filled with a 500 ns sentinel so it's never treated as a free path.

### Dispatch order

Each LLC has its own dispatch queueand a task is queued on the LLC of the CPU it is assigned to (`task_cpu(p)`) on every enqueue path. On a task dispatch:

1. Try the calling CPU's local LLC first covers most dispatches with zero cross-LLC traffic
2. If nothing there can run on this CPU, build a steal mask of LLCs flagged non-empty and try the lowest-ETD-cost one first
3. Fall through remaining LLCs in order

A non-empty flag is cleared only when the queue is actually emptyand there is no minimum queue depth for stealing. On single-LLC systems the steal path is eliminated at load time: `nr_llcs` is a frozen rodata value, so the verifier drops the dead branch.

### Hybrid P/E-core steering

On Intel hybrid systems, when the kernel's idle pick is an E-core, the idle path scans the P-cores the task may run on, in index order, for one whose physical core has no SMT sibling, falling back to the first allowed P-core. The scan doesn't test idleness. The kernel's idle search is repeated from that CPUand its result is used only if the kernel reports it idle. The first search has already claimed the E-core's idle bit, so when the retry succeeds, that E-core stays marked busy until it next passes through idle.

### Preemption kick

When a T0 or T1 task is queued while every CPU is busy, a victim CPU in the same LLC is kicked immediately: a CPU running T3 work, else one running T2 work. The task must be allowed to run there, the CPU must not be running a lock holder inside its protection window, and no other enqueue may have claimed it already (an atomic claim bit per CPU, released when the victim switches tasks). Up to Gen 5 the lowest-numbered candidate was always kicked, whether or not the task could run there. T0 and T1 CPUs are never kicked to run another latency-critical task, and T2 or T3 enqueues never kick.

### Slice expiry

When a task's slice ends while it is still runnable, `ops.dispatch` compares the deadline it would get on re-queue with the head of its LLC queue and keeps it running if it is no later. Up to Gen 5 the queue head always won, even a T3 task over a T2 one. Tasks that called `sched_yield()` always yield. The tick ends a slice by setting it to 0, with no self-IPI.

---

## Initial Classification

Before any EWMA data exists, tasks start from two signals:

* **Nice value:** nice < 0 → T0, nice > 10 → T3, otherwise → T1
* **Kthreads at nice 0:** start at T1, not T0 `kcompactd`, `kswapd` and similar shouldn't start at max priority

Average runtime is seeded at the midpoint of the initial tier's expected range rather than zero (T0 50µs, T1 1050µs, T3 8001µs). Starting from zero let any task with a short first bout masquerade as T0 for several scheduling windows.

Nice is read once, when the scheduler first sees a task. Renicing a running task does not reseed its tier.

---

## Scheduler Architecture

```
select_cpu
  ├── scx_bpf_select_cpu_dfl() finds an idle CPU → direct dispatch with the task's own slice
  │     (hybrid: if the pick is an E-core, repeat the search from a P-core hint, keep it only if idle)
  └── All busy → IRQ context or ksoftirqd waker? stamp CAKE_FLOW_IRQ_WAKE; return prev_cpu

enqueue
  ├── not a wakeup (slice expiry, kick, yield, new task) → own tier, fresh deadline, lock boost once
  ├── slept >500ms? → move avg_runtime halfway to the tier midpoint
  ├── IRQ_WAKE → T0 (T3 tasks: T2); waker mailbox → promote to waker tier (floor T1; T3: T2)
  ├── new-flow / lock-boost → deadline advance, capped within the tier
  ├── vtime = now + tier budget - advance → per-LLC DSQ
  └── T0/T1 → claim and kick an allowed T3 (else T2) CPU in the LLC, skipping fresh lock holders

dispatch
  ├── prev runnable and due no later than the LLC queue head → keep it running (not after a yield)
  ├── pull from local LLC DSQ
  └── if nothing runnable: ETD-ordered steal from other LLCs

running  → stamp last_run_at, release kick claim, publish tier to mailbox, set tier bitmask
tick     → past next_slice with work queued → slice = 0; DVFS update
stopping → clear tier bitmask; lock state → one-shot boost; real sleep → cadence sample;
           burst + EWMA + DRR++ + frame-cadence cap
```

---

## Overhead

The cycle counts below were measured against an earlier revision and have not been re-profiled since. The notes column records what Gen 5 and Gen 6 changed; the numbers don't reflect it.

The added cost relative to a minimal sched_ext skeleton was approximately 20%, concentrated in `select_cpu` and `enqueue`.

| Function | Added cost | Notes |
| :--- | :--- | :--- |
| `select_cpu` | ~2c on dominant path | Gen 6 reads the preempt count on the all-busy path; task storage only for IRQ-context wakeups there |
| `enqueue` | +6c steady-state | Mailbox read is the main cost; Gen 6 kicks read the claim mask and test the task's cpumask per candidate |
| `dispatch` | not re-measured | Gen 6: task-storage lookup and a DSQ peek when the previous task is still runnable |
| `tick` | +2c | Up to two `scx_bpf_dsq_nr_queued()` reads once past `next_slice`; Gen 6 removed the unreachable Phase 2 and its deprecated `scx_bpf_cpu_rq()` call |
| `running` | +11c | Mailbox write + tier bitmask set + jitter EWMA update |
| `stopping` | +5c | Tier bitmask clear + burst accumulator; Gen 6 adds sleep/cadence bookkeeping |
| lock probes | per futex call | Task-storage lookup + mailbox store on lock acquire/release |

To measure the current per-call cost of every callback on a running system (mean ns per call over 10 seconds):

```bash
sudo sysctl -qw kernel.bpf_stats_enabled=1 && sleep 10 && sudo bpftool prog show | awk '/ name imperator_/ {n=""; t=0; c=0; for (i=1;i<=NF;i++) {if ($i=="name") n=$(i+1); if ($i=="run_time_ns") t=$(i+1); if ($i=="run_cnt") c=$(i+1)} if (c) printf "%-16s %8.1f ns/call %12d calls\n", n, t/c, c}'; sudo sysctl -qw kernel.bpf_stats_enabled=0
```

---

## Known Limitations

* **IRQ-wake scope** every task waking from a timed sleep gets a one-dispatch boost, background tasks included (bulk tasks only to T2). The boost was effectively off before Gen 6, so earlier A/B results were measured without it; `--no-irq-boost` restores that.
* **Lock-holder detection** keyed on futex return values, so condvar waiters are flagged too; the protection window bounds the effect.
* **Frame-cadence cap** a periodic background job shaped like a game thread is also held at T2.
* **Victim choice** within a tier, candidates are tried lowest index first.
* **CPU count** per-CPU arrays hold 64 entries and CPU indices are masked with `& 63`; nothing refuses to load on larger systems.
* **Build** with clang 21, `bpf_compat.h`'s `__atomic_load_n` path needs `-mcpu=v4`.
* **Validation** Gen 6 was verified in a QEMU/KVM guest of a 7.2 kernel with a synthetic workload, not yet A/B tested in real games.

The full lists of Gen 5 and Gen 6 changes are in the [README](../README.md#11-gen-5-changes).

---

## Research Sources

| Feature | Derived from |
| :--- | :--- |
| DRR++ tier queuing | Network CAKE queueing discipline |
| EWMA classification + per-LLC DSQ | scx_cake (CAKE original) |
| Asymmetric EWMA, graduated backoff, ETD calibration | scx_cake (CAKE original) |
| IRQ-source wakeup detection | scx_lavd (`lavd_select_cpu`) |
| Waker tier inheritance | scx_lavd (`lat_cri_waker/wakee`) |
| Lock-holder detection and protection | scx_lavd (`lock.bpf.c`, `consume_prev()`), bounded by a time window |
| Frame-cadence cap | scx_lavd (`wait_freq`) |
| IRQ-context detection via preempt count, distinct and affinity-aware preemption victims | scx_lavd |
| Burst-since-last-sleep classification | scx_lavd (`acc_runtime`; `max(avg_runtime, acc_runtime)` in `calc_sum_runtime_factor()`) |
| Per-tier deadline ordering | Original (Gen 5) |
