# scx_imperator

A gaming-focused CPU scheduler built on [sched_ext](https://github.com/sched-ext/scx). It classifies tasks by how much CPU they use between sleeps and routes them through a 4-tier priority system. High-priority work like audio callbacks and mouse input gets CPU time first, bulk work like compilers gets it last.

The three things that make it different from a generic SCX scheduler:

* **IRQ-wake boosting** when hardware (GPU vsync, audio DMA, network) or a timer wakes a task, that task runs at max priority for that one dispatch regardless of its history
* **Waker inheritance** a high-priority task waking a lower-priority one temporarily lifts the wakee's priority, keeping producer-consumer chains tight
* **Deadline-bounded tiers** tasks that arrive together run in strict tier order, but every tier has a budget, so a lower-tier task that has waited long enough goes ahead of newer higher-tier work instead of starving

Lock-holder protection is implemented in `lock.bpf.c` but not loaded by the current loader (see [Lock-holder protection](#lock-holder-protection)).

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

Each sample is a burst: CPU time summed from the moment the task wakes until it sleeps, across any preemptions in between. While a burst is still in progress, the running total can only raise the average; promotion waits until the task actually sleeps. Up to Gen 4 each preempted bout was sampled on its own. A preempted bout ends at the scheduler's own slice boundary, so under contention every CPU-bound task drifted to T2and a render thread flipped between T1 and T2 depending on where its burst was cut.

A few things that keep classification stable:

* **Hysteresis** promotion requires the average to fall below 90% of the tier gate (90µs / 1800µs / 7200µs).
* **Overrun demotion** on each full reclassification pass, an 8-bit shift register records whether the sample exceeded 1.5× the tier gate (150µs / 3ms / 12ms). When 4 of the last 8 recorded samples did, the task drops one tier. An average above 24ms with a stable tier forces T3.
* **Graduated backoff** once a task's tier has been stable for 3 stops, the full reclassification path runs less often (T0: every 1024th stop, T1: every 128th, T2: every 32nd, T3: every 16th). The EWMA still updates every stop.
* **Post-sleep recovery** when a task wakes after sleeping over 500ms and is queued because no CPU is idle, its average moves halfway toward the midpoint of its current tier (50µs / 1050µs / 5000µs / 8001µs). Prevents a game thread that spent a loading screen at T3 from needing 10+ bursts to recover. Wakeups placed directly on an idle CPU skip this step.

Fork inheritance and exec reset are coded in `imperator_init_task` but never run. Task storage is created in `ops.enable`, which runs after `init_task`and sched_ext has no exec hook. Forked threads are seeded from their own nice value like any other new taskand classification carries across `exec`.

---

## Profiles

Three profiles, selectable at launch with `-p`. `gaming` is an accepted alias for `default`.

| Profile | Base Quantum | New-Flow Bonus | Budgets T0 / T1 / T2 / T3 | Slices T0 / T1 / T2 / T3 |
| :--- | :--- | :--- | :--- | :--- |
| **Default** (`gaming`) | 2ms | 8ms | 1.5 / 8 / 20 / 100ms | 0.5 / 2 / 4 / 8ms |
| **Esports** | 1ms | 4ms | 1.5 / 4 / 20 / 50ms | 0.25 / 1 / 2 / 4ms |
| **Sim** | 4ms | 8ms | 3 / 8 / 80 / 200ms | 1 / 4 / 8 / 16ms |

Tier multipliers are the same on every profile: T0 0.25×, T1 1×, T2 2×, T3 ~4× (4095/1024). A task re-queued after preemption gets one base quantum regardless of tier.

**Default** is the desktop gaming profile and needs no other flags. **Esports** halves the quantum and tightens the T1 and T3 budgets for minimum worst-case latency, at the cost of more context switches. **Sim** is for strategy, 4Xand open-world games whose simulation or streaming thread dominates: a 4ms quantum and larger T2 and T3 budgets.

The `--starvation` flag scales all tier budgets proportionally from the T3 base, preserving inter-tier ratios and therefore the tier order. `--quantum` and `--new-flow-bonus` override the profile's values, in µs.

Up to Gen 4 the BPF side read compile-time copies of the quantum (2ms) and new-flow bonus (8ms), so Esports, Simand both override flags had no effect on slices or the bonus.

---

## Context Signals

These features act on top of the base tier system. They don't modify a task's permanent classification; they affect one dispatch or one queue position at a time.

### IRQ-wake boost

When a wakeup originates from a hardware interrupt, NMI, softirq, or ksoftirqd, the woken task runs at T0 for that one dispatch. The flag is consumed and gone. This matters because a task woken by a mouse click or audio DMA completion may not yet have a T0 EWMA history; it might be new. The hardware urgency shouldn't wait for behavioral evidence to accumulate.

Timer expirations count as interrupts. On non-PREEMPT_RT kernels, hrtimer sleepers (nanosleep, futex, polland epoll timeouts) expire in hardirq context, so a task waking from a timed sleep is boosted too. That covers sleep-based frame limitersand also any background task that wakes on a timer. On the idle path the boosted task gets the T0 slice. When every CPU is busy it is queued with a T0 deadline, which kicks a victimand it keeps its own tier's slice.

### Waker tier inheritance

On queued wakeups, the woken task's tier is compared against the tier of the CPU that woke it (read from a per-CPU mailbox updated on every context switch). If the waker's tier is lower (higher priority), the wakee is promoted to match it, floored at T1. So a T0 audio thread waking a T2 event dispatcher promotes it to T1 for that dispatch. The floor keeps T0 for tasks that earn it through their own history or an IRQ wake. The promotion changes queue order and kick eligibility; the slice stays the wakee's own.

On 6.15+ kernels a wakeup's `ops.enqueue` runs on the waker's CPU, so the mailbox read is the waker's tier. On 6.12 to 6.14, wakeups delivered through the ttwu wakelist run `ops.enqueue` on the target CPU and read that CPU's mailbox instead.

### Lock-holder protection

Not active in this build. Every program in `lock.bpf.c` is declared `SEC("?fexit/...")` or `SEC("?tracepoint/...")`, which libbpf does not auto-loadand the loader only calls `attach_struct_ops()`, so the lock-holder flag is never set. On a running system, this prints 0 when the probes aren't loaded:

```bash
sudo bpftool prog show | grep -c imperator_fexit
```

When the probes are loaded, the flag advances the holder's queue deadline by the new-flow bonus, capped within its tier, so it sorts ahead of same-tier tasks and releases the lock sooner. The tick-side skip (up to 4 skipped starvation preemptions) cannot fire: it sits in the tick's starvation pathand because every budget is longer than its slice, the slice check kicks and returns first whenever anything is queued.

Issues to fix before enabling it:

* `futex_wait` returning 0 means the task was woken, not that it owns a lock, so condvar and job-queue waiters get flagged too
* The flag clears only when the task itself calls `futex_wake`; LAVD clears its futex boost at every `ops.stopping`
* `futex_waitv`, which Proton's fsync uses, isn't hooked

Coverage gaps: uncontended locks never enter the kernel, so they are invisible to this path. `FUTEX_WAIT_REQUEUE_PI` is covered at the waiter's own syscall return, which can lag the ownership transfer during the waker's requeue call by up to one scheduling round-trip.

### Dispatch latency telemetry

Every queued task measures how long it waited between entering the dispatch queue and running, tracked as a per-task α=1/8 EWMA (`jitter_ewma_us`). Collection (`enable_stats`) is switched on by `-s`/`--stats`, which logs a summary roughly every 60 seconds, or by the TUI (`-v`/`--verbose`). Tasks placed directly on an idle CPU never enter the queue and aren't sampled. Up to Gen 4, `enable_stats` was a plain `const` that clang folded to `false`, so every counter stayed at zero whatever the flags.

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

When a T0 or T1 task is queued while every CPU is busy, a victim CPU in the same LLC is kicked immediately: the lowest-numbered CPU running T3 work, else the lowest-numbered CPU running T2 work. T0 and T1 CPUs are never kicked to run another latency-critical taskand T2 or T3 enqueues never kick.

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
  ├── IRQ context? → stamp CAKE_FLOW_IRQ_WAKE on tctx
  ├── scx_bpf_select_cpu_dfl() finds an idle CPU (SCX_WAKE_SYNC placement is the kernel's)
  │     → hybrid: if the pick is an E-core, repeat the search from a P-core hint, keep it only if idle
  │     → direct dispatch via SCX_DSQ_LOCAL_ON
  └── All busy → return prev_cpu

enqueue
  ├── now = scx_bpf_now(), LLC = cpu_llc_id[task_cpu(p)]
  ├── not a wakeup (slice expiry, kick, yield, new task) → queue at own tier, base-quantum slice
  ├── slept >500ms? → move avg_runtime halfway to the tier midpoint
  ├── Feature 1: IRQ_WAKE flag → tier = T0 (one-shot, consumed here)
  ├── Feature 2: waker mailbox read → promote wakee tier if waker is higher (floor T1)
  ├── Feature 3: new-flow / lock-holder flag → deadline advance, capped within the tier
  ├── vtime = now + tier budget - advance
  ├── insert into per-LLC DSQ
  └── T0/T1: kick the lowest-numbered T3 (else T2) CPU in the LLC via bitmask

dispatch
  ├── pull from local LLC DSQ
  └── if nothing runnable: ETD-ordered steal from other LLCs

running  → stamp last_run_at, publish tier to per-CPU mailbox, set tier bitmask
tick     → past next_slice with a task queued in the LLC or local DSQ → self-kick; DVFS update
stopping → clear tier bitmask (before reclassify), add bout to burst, EWMA on burst + DRR++
```

---

## Overhead

The cycle counts below were measured against an earlier revision and have not been re-profiled since. The notes column records what Gen 5 changed; the numbers don't reflect it.

The added cost relative to a minimal sched_ext skeleton was approximately 20%, concentrated in `select_cpu` and `enqueue`.

| Function | Added cost | Notes |
| :--- | :--- | :--- |
| `select_cpu` | ~2c on dominant path | Task storage fetched only on IRQ-context wakeups; the SYNC fast path and the scratch writes are gone |
| `enqueue` | +6c steady-state | Mailbox read (Feature 2) is the main cost; Gen 5 adds `scx_bpf_now()` and `scx_bpf_task_cpu()` calls |
| `dispatch` | not re-measured | One `scx_bpf_dsq_nr_queued()` read when a pull fails |
| `tick` | +2c | Up to two `scx_bpf_dsq_nr_queued()` reads once past `next_slice`; no more per-tick self-kicks on a lone busy CPU |
| `running` | +11c | Mailbox write + tier bitmask set + jitter EWMA update |
| `stopping` | +5c | Tier bitmask clear + burst accumulator update |
| `lock_bpf` probes | ~50ns | Not loaded |

To measure the current per-call cost of every callback on a running system (mean ns per call over 10 seconds):

```bash
sudo sysctl -qw kernel.bpf_stats_enabled=1 && sleep 10 && sudo bpftool prog show | awk '/ name imperator_/ {n=""; t=0; c=0; for (i=1;i<=NF;i++) {if ($i=="name") n=$(i+1); if ($i=="run_time_ns") t=$(i+1); if ($i=="run_cnt") c=$(i+1)} if (c) printf "%-16s %8.1f ns/call %12d calls\n", n, t/c, c}'; sudo sysctl -qw kernel.bpf_stats_enabled=0
```

---

## Known Limitations

* **Heavy main threads** a thread that needs more than 8ms of CPU per frame classifies as T3 and sorts behind T2 work (only possible below 125 fps). Candidate fixes: raise `TIER_GATE_T2`, or require a low wakeup rate before T3.
* **IRQ-wake scope** every task waking from a timed sleep gets a one-dispatch T0 boost, background tasks included.
* **Preemption burst credit** never accrues: it keys on `SCX_ENQ_PREEMPT` in `ops.enqueue`, which the kernel never passes there.
* **Tick starvation path** the tick's starvation kick and lock-holder skip cannot fire; bounded waiting comes from deadline ordering. `starvation_preempts` and `lock_holder_skips` in `--stats` always read 0.
* **Kick victim choice** always the lowest-numbered candidate, so a burst of T0/T1 wakeups kicks the same CPU until it switches tasks.
* **Slice expiry** `ops.dispatch` takes the queue head without comparing it to the task whose slice just ended.
* **CPU count** per-CPU arrays hold 64 entries and CPU indices are masked with `& 63`; nothing refuses to load on larger systems.
* **Build** with clang 21, `bpf_compat.h`'s `__atomic_load_n` path needs `-mcpu=v4`.

The full list of Gen 5 changes is in the [README](../README.md#11-gen-5-changes).

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
| Burst-since-last-sleep classification | scx_lavd (`acc_runtime`; `max(avg_runtime, acc_runtime)` in `calc_sum_runtime_factor()`) |
| Per-tier deadline ordering | Original (Gen 5) |
