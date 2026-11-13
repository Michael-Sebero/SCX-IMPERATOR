## **I.M.P.E.R.A.T.O.R**

**IRQ-Aware · Multitiered · Preemptive · EWMA · Relayed · Aging · Topology · Overrun · Runtime**

| | Word | What it refers to |
| :--- | :--- | :--- |
| **I** | IRQ-Aware | Wakeups from hardware interrupts, softirqs, ksoftirqd and timers run at T0 for one dispatch; bulk (T3) tasks at T2 (§4) |
| **M** | Multitiered | Four tiers, T0 Critical to T3 Bulk (§3) |
| **P** | Preemptive | A queued T0/T1 wakeup claims and kicks a T3 (else T2) CPU in its LLC that the task may run on; a task past its slice yields only to queued work with an earlier deadline (§6, §7) |
| **E** | EWMA | Tier comes from an asymmetric moving average: promotions settle in ~4 samples, demotions in ~16 (§3) |
| **R** | Relayed | On a queued wakeup, the waker's tier is relayed to the task it wakes, floored at T1 (T2 for bulk tasks), for that dispatch (§4) |
| **A** | Aging | Queue order is enqueue time plus a per-tier budget, so a waiting task overtakes newer higher-tier work once it has waited out the gap (§3) |
| **T** | Topology | Per-LLC queues, ETD-ordered cross-LLC stealing, hybrid P/E-core steering (§7) |
| **O** | Overrun | 4 of the last 8 samples over 1.5× the tier gate drops a task one tier (§3) |
| **R** | Runtime | Classification input is observed CPU time between waking and sleeping, plus sleep cadence for frame-paced threads (§3) |

> **ABSTRACT**: `scx_imperator` is a BPF CPU scheduler built on [sched_ext](https://github.com/sched-ext/scx), designed for **gaming workloads** on modern AMD and Intel hardware. It classifies every task by observed runtime behavior and routes work through a 4-tier priority system high-priority tasks like audio callbacks and mouse input get CPU time first, bulk work like compilers gets it last.
>
> - **4-Tier Classification** Tasks sorted by an asymmetric EWMA of burst length (CPU time between waking and sleeping) into Critical / Interactive / Frame / Bulk
> - **Deadline-Bounded Priority** Each queued task is keyed by its enqueue time plus a per-tier budget: tasks that arrive together run in strict tier order, and a task that has waited out its budget gap goes ahead of newer higher-tier work, so no tier starves
> - **IRQ-Wake Boosting** Wakeups from hardware interrupts and timers (GPU vsync, audio DMA, network, timed sleeps) promote that task to T0 for one dispatch (bulk tasks to T2)
> - **Waker Tier Inheritance** High-priority task waking a lower-priority one lifts the wakee's tier, keeping producer-consumer chains tight
> - **Lock-Holder Protection** A task that just acquired a futex-based lock (including Proton's `futex_waitv`) is not chosen as a preemption victim, may run briefly past its slice, and re-queues slightly ahead of its tier if preempted while holding it
> - **Frame-Cadence Classification** A thread that sleeps at 30 fps or faster is held at T2 even when its bursts exceed 8ms, so a CPU-heavy game main thread is not treated as bulk work
> - **ETD Calibration** Startup CAS ping-pong measures actual inter-core latency; on systems with three or more LLCs, cross-LLC work stealing tries the empirically-cheapest LLC first, falling back to index order before calibration completes
> - **Hybrid P/E-Core Steering** On Intel hybrid systems, when the kernel's idle pick is an Efficiency core, the idle path repeats the kernel's idle search from a Performance-core hint and uses the result only if the kernel reports it idle
> - **Dispatch Latency Telemetry** Every queued task tracks its own scheduling latency (enqueue-to-run) as a per-task EWMA; mean dispatch latency is shown live in the TUI summary bar and clipboard export, or logged periodically in headless mode via `--stats`
> - **Desktop-First DVFS** Every tier requests full CPU clock; no power-saving throttle on background work, since `scx_imperator` targets mains-powered desktops. The request only takes effect under the schedutil governor (§5)
>
> Gen 6 (§12) made the IRQ-wake boost and lock-holder protection actually run (both were dead code before), removed the inactive preemption burst credit, and fixed burst accounting so CPU-bound tasks reach T3.

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
- [10. Known Limitations](#10-known-limitations)
- [11. Gen 5 Changes](#11-gen-5-changes)
- [12. Gen 6 Changes](#12-gen-6-changes)

---

## 1. Quick Start

```bash
# Prerequisites: Linux Kernel 6.12+ with sched_ext, Rust toolchain

# Clone and build
git clone https://github.com/Michael-Sebero/SCX-IMPERATOR
cd SCX-IMPERATOR && sh build.sh

# Install
sudo install -m 755 target/release/scx_imperator /bin/scx_imperator

# Run (requires root) — uses the Default profile, tuned for desktop gaming
sudo scx_imperator

# Competitive/esports profile — tightest worst-case latency, more context-switch overhead
sudo scx_imperator -p esports

# Headless telemetry: logs a stats summary roughly every 60 seconds
sudo scx_imperator -s

# A/B switches for the Gen 6 context signals
sudo scx_imperator --lock-boost off     # auto (default) | fexit | tracepoint | off
sudo scx_imperator --no-irq-boost
```

[Full Documentation](https://github.com/Michael-Sebero/SCX-IMPERATOR/blob/main/docs/imperator-documentation.md)

---

## 2. Philosophy

Traditional schedulers (CFS, EEVDF) optimize for **fairness** if a game and a compiler both run, each gets roughly 50% CPU time. For gaming, this creates two problems:

1. **Latency inversion**: A 50µs input handler waits behind a 50ms compile job
2. **Frame jitter**: Game render threads get preempted mid-frame by background work

**scx_imperator's answer**: reject negotiated fairness in favor of imposed, structural rank with a bounded wait. Tasks are classified by *behavior* (how much CPU they use between sleeps), not by type or nice value. Once a task is ranked, its tier wins against everything queued at the same moment, with no per-dispatch negotiation. Rank is not unlimited: every tier has a deadline budget, so a lower-tier task that has waited long enough goes ahead of newer higher-tier work instead of starving (§3). Short-burst tasks (input, audio) get instant priority. Long-running tasks (compilers) get larger time slices but lower priority. The system self-tunes no manual tagging or cgroup setup required.

**How that rank gets exercised**: enforcement keys off tier alone. Preemption kicks, deadline budgets, and slice lengths all come from the tier, not from per-task negotiation. But the machinery that *computes* placement leans the other way on purpose: idle-CPU selection, including where SYNC wakeups land, is delegated to the kernel's own atomic idle-claiming rather than reimplemented in BPF (§6); hybrid P-core placement (§7) is offered only as a hint and used only when the kernel reports the resulting CPU idle; a T2/T3 preemption kick that looked correct in theory was removed after A/B testing showed a measurable frame-rate regression. Rank decides the order, budgets bound the wait. Getting there isn't guesswork.

---

## 3. 4-Tier System

Every task is classified into one of four tiers based on an **EWMA** (Exponentially Weighted Moving Average) of its burst length: the CPU time it uses between waking and sleeping. Classification is automatic and continuous tasks move between tiers as their behavior changes.

### Tier Gates

| Tier | Name | avg_runtime | Examples | Deadline budget (Default profile) |
| :--- | :--- | :--- | :--- | :--- |
| **T0** | Critical | < 100µs | IRQ handlers, mouse input, audio callbacks | 1.5ms |
| **T1** | Interactive | < 2ms | Compositor, game physics, AI | 8ms |
| **T2** | Frame | < 8ms | Game render threads, video encoding | 20ms |
| **T3** | Bulk | ≥ 8ms | Compilation, background indexing | 100ms |

### Queue Order

Each LLC has one dispatch queue sorted by a single key, the task's **deadline**: `enqueue time + tier budget`. Budgets rise with tier in every profile, so tasks that arrive together always run T0 → T1 → T2 → T3, and there is no per-dispatch branching to enforce it. A waiting task is not passed forever: once it has waited the gap between its own budget and the next tier's, newer arrivals of that tier sort behind it. On the Default profile, new T0 work stops passing a queued T1 task after 6.5ms, new T1 work stops passing a queued T2 task after 12ms, and new T2 work stops passing a queued T3 task after 80ms.

Up to Gen 4 the key was `(tier << 56) | timestamp`: strict priority with no aging. A queued T3 task could wait behind T0–T2 work indefinitely, and sustained saturation ended with the sched_ext watchdog (30 s default) disabling the scheduler. See [§11](#11-gen-5-changes).

> [!NOTE]
> Budgets vary by profile — see [§5 Profiles](#5-profiles) for the full table. The values above are the **Default** profile's, which doubles as `--profile gaming`. T0 and T2 match **Esports** exactly (1.5ms / 20ms) under the desktop policy that audio/input/render latency shouldn't be sacrificed on a system with CPU headroom to spare; T1 and T3 stay looser to favor smoother frame pacing and fewer context switches under normal play.

> [!TIP]
> Game render threads with 2–8ms of CPU per frame classify as T2, physics/AI at 0.5–2ms as T1, input handlers under 100µs as T0. A thread lands in T3 when it runs 8ms or more between sleeps: shader compilation and loading screens. A main thread that needs more than 8ms of CPU per frame but still sleeps every frame is held at T2 by the frame-cadence cap (Gen 6; up to Gen 5 it classified as T3, sorted behind T2 work and was the first preemption victim).

### How Classification Works

1. **Initial placement**: Based on `nice` value `nice < 0` → T0, `nice 0–10` → T1, `nice > 10` → T3. Kthreads at nice 0 start at T1, not T0. The nice value is read once, when the scheduler first sees the task; renicing a running task does not reseed its tier.
2. **Runtime seeding**: avg_runtime is seeded at the midpoint of the initial tier's expected range (T0 50µs, T1 1050µs, T3 8001µs), not zero. Starting from zero lets any task with a short first bout masquerade as T0 for several windows.
3. **Burst accounting**: The sample fed to the EWMA is CPU time summed from the moment a task wakes until it sleeps, across any preemptions in between (`burst_acc_us`). While a burst is still in progress (the task was preempted, not blocked), its running total is a lower bound, so it can only raise the average; promotion waits until the task actually sleeps. "Sleeps" means the task left `TASK_RUNNING`: the kernel also calls `ops.stopping(p, runnable=false)` when a running task is dequeued for a property change (affinity, nice, class, cgroup), and up to Gen 5 each of those ended the burst, so a pure CPU spinner sat in T2. Up to Gen 4 each preempted bout was sampled on its own, and a preempted bout ends at the scheduler's own slice boundary, so under contention every CPU-bound task drifted to T2.
4. **EWMA authority**: After ~4 bursts, the EWMA avg_runtime becomes authoritative. A nice -5 task that runs 50ms bursts reclassifies to T3 regardless of nice value.
5. **Asymmetric convergence**: Promotions (shorter runtime) converge in ~4 samples (α = 1/4); demotions (longer runtime) take ~16 (α = 1/16). Hysteresis gates stop oscillation at the boundaries: promotion requires the average to fall below 90% of the gate (90µs / 1800µs / 7200µs).
6. **Overrun demotion**: On each full reclassification pass, an 8-bit shift register records whether the sample exceeded 1.5× the tier gate (150µs / 3ms / 12ms, T0–T2). When 4 of the last 8 recorded samples did, the task drops one tier. An average above 24ms with a stable tier forces T3 outright.
7. **Frame-cadence cap**: Every real sleep feeds an α = 1/4 average of the sleep-to-sleep period (`cadence_us`). A task whose period is at most 34ms (≈ 30 Hz or faster) and whose average burst is under 7/8 of that period is held at T2 instead of T3, whatever the hard-demote cap or overrun register say. That covers a game main or simulation thread running 8–14ms of a 16.6ms frame; a compiler or a worker draining a job queue either sleeps rarely or barely at all between jobs and still reaches T3. The signal comes from LAVD's `wait_freq`.
8. **Graduated backoff**: Once a task's tier has been stable for 3 consecutive stops, the full reclassification path slows: T0 every 1024th stop, T1 every 128th, T2 every 32nd, T3 every 16th. The EWMA still updates every stop, and a spot check resets the backoff as soon as the new average would cross a gate.
9. **Post-sleep recovery**: When a task wakes after sleeping more than 500ms and is queued because no CPU is idle, its average is moved halfway toward the midpoint of its current tier (50µs / 1050µs / 5000µs / 8001µs) before it is queued, so a thread that spent a loading screen at T3 doesn't need 10+ bursts to recover. Wakeups placed directly on an idle CPU skip this step.
10. **Fork and exec**: Every new task, forked threads included, is seeded from its own nice value, and classification carries across `exec` (sched_ext has no exec hook). The fork-inheritance and exec-reset branches that used to sit in `imperator_init_task` never ran, because task storage is created in `ops.enable`, after `init_task`; Gen 6 removed them.

### DRR++ Deficit Tracking

Adapted from network CAKE's flow fairness algorithm:

- Each task starts with a **deficit** of quantum + new-flow bonus (10ms on the Default profile)
- Each execution bout consumes deficit proportional to runtime
- While deficit remains, the task's queue deadline is advanced by the new-flow bonus (8ms on Default); for T1–T3 the advance is capped just below the gap to the next tier's budget, so it only reorders a task within its own tier
- When deficit exhausts → new-flow bonus removed → task competes normally

The bonus applies from a task's first wakeup onward. A brand-new task's very first enqueue is not a wakeup: if no CPU is idle it is queued at its seeded tier without the advance.

---

## 4. Context Signals

These features act on top of the base tier system: IRQ-wake boost, waker tier inheritance, lock-holder protection, and dispatch latency telemetry. None of them modify a task's permanent classification — they affect one dispatch or one queue position at a time. Each boost can lift a T3 (bulk) task to T2 at most, so bulk work never gains a tier that can trigger a preemption kick.

### IRQ-Wake Boost

When a wakeup originates from a hardware interrupt, NMI, softirq, or ksoftirqd and every CPU is busy, the woken task is queued at T0 for that one dispatch (a T3 task at T2). The flag is consumed immediately. This matters because a task woken by a mouse click or audio DMA completion may not yet have a T0 EWMA history — the hardware urgency shouldn't wait for behavioral evidence to accumulate. The task keeps its own tier's slice.

Timer expirations count as interrupts. On non-PREEMPT_RT kernels, hrtimer sleepers (`nanosleep`, futex/poll/epoll timeouts, timerfd) expire in hardirq context, so any task waking from a timed sleep is boosted the same way. That covers sleep-based frame limiters and audio periods, and also any background task that wakes on a timer; the T3→T2 cap keeps the latter from preempting anything.

Wakeups placed directly on an idle CPU are not boosted: the task runs immediately, and up to Gen 5 the only effect there was cutting its slice to the T0 slice (a render thread woken by a GPU-fence IRQ got 0.5ms instead of 4ms).

Interrupt context is detected by reading the per-CPU preempt count (the helpers LAVD uses from scx's `bpf_experimental.h`). **Up to Gen 5 this feature only fired for ksoftirqd wakeups**: `bpf_compat.h` declared `bpf_in_hardirq()` and friends as weak kfuncs, which no mainline kernel exports, so they resolved to NULL. `--no-irq-boost` turns the boost off for A/B comparisons.

### Waker Tier Inheritance

On queued wakeups (all CPUs busy), the woken task's tier is compared against the tier of the CPU that woke it (read from a per-CPU mailbox updated on every context switch). If the waker's tier is lower-numbered (higher priority), the wakee is promoted to match it, floored at T1 — and at T2 for a T3 wakee. A T0 audio thread waking a T2 event dispatcher promotes it to T1 for that dispatch. The promotion changes queue order and kick eligibility; the slice stays the wakee's own. LAVD caps inherited latency criticality at a quarter of the wakee's own; the bulk-task cap is the IMPERATOR equivalent.

On 6.15+ kernels, `ops.enqueue` for a wakeup runs on the waker's CPU, so the mailbox read is the waker's tier. On 6.12–6.14, wakeups delivered through the ttwu wakelist run `ops.enqueue` on the target CPU and read that CPU's mailbox instead.

### Lock-Holder Protection

Adapted from LAVD's futex boost, with bounds. A task becomes a lock holder when `futex_wait`, `futex_waitv` (Proton's fsync), `futex_wait_requeue_pi` or `futex_lock_pi` returns a wake/acquire, and stops being one when it calls `futex_wake`, `futex_wake_op` or `futex_unlock_pi`, or stops running. While it holds the flag and the lock is younger than a quarter quantum (0.5ms on Default):

1. Its CPU is skipped when a T0/T1 wakeup picks a preemption victim
2. When its slice runs out, `ops.dispatch` keeps it running once for that same window instead of switching

If it is switched out still holding the flag (preempted or slice-expired), its re-queue gets the within-tier deadline advance (the new-flow bonus, capped below the next tier's gap) once. A task that blocks gets no boost: it most likely released the lock.

The window exists because `futex_wait` returning 0 means "woken", which is also what a condvar or job-queue waiter sees. LAVD keeps such a task protected until it calls `futex_wake` or stops, which can cover a long CPU-bound run.

Probes are fexit programs on the kernel futex functions, with the `syscalls:sys_{enter,exit}_futex*` tracepoints as a fallback (`--lock-boost auto|fexit|tracepoint|off`, default `auto`; the log says which set attached). Up to Gen 5 `lock.bpf.c` was never compiled into the scheduler, so none of this ran.

> [!NOTE]
> **Coverage gaps**: Uncontended locks never enter the kernel and are invisible to this path. `FUTEX_WAIT_REQUEUE_PI` (glibc condvar + PI mutex) is covered: the waiter's call returns only once it owns the mutex, so the flag is set when that call returns, which can lag the ownership transfer during the waker's requeue by up to one scheduling round-trip.

### Dispatch Latency Telemetry

Every task records a timestamp when it enters the dispatch queue on a wakeup (`enqueue_time`) and measures how long it waited before actually running. This per-task dispatch latency is tracked as an α=1/8 EWMA stored in `jitter_ewma_us`.

Each context switch accumulates the current EWMA sample into two per-CPU counters (`nr_jitter_ewma_sum`, `nr_jitter_ewma_count`) in `imperator_stats`. The TUI aggregates these across all CPUs and displays the mean dispatch latency live in the summary bar and in the clipboard export.

Collection (`enable_stats`) is switched on by `-s`/`--stats` or by the TUI (`-v`/`--verbose`). With `--stats`, a summary line is logged roughly every 60 seconds (dispatches, tier counts, tick preemptions, preemption kicks, kept-running tasks, lock-holder protections, IRQ and waker boosts, cadence holds, mean dispatch latency), and the raw per-CPU counters remain readable via `bpftool map dump` on the scheduler's `bss` map.

Tasks placed directly on an idle CPU from `select_cpu` never enter the queue and have no wait to record, so they aren't sampled. That includes SYNC wakeups the kernel places on an idle CPU.

### Debug Dump

`imperator_dump_task` adds one line per task to the sched_ext debug dump (SysRq-D, or the dump printed when the scheduler exits with an error): tier, stability, average burst, current burst, sleep cadence, deficit, slice, extended flags and the overrun register. On current kernels the SysRq-D dump goes to the `sched_ext/sched_ext_dump` trace event:

```bash
echo 1 | sudo tee /sys/kernel/tracing/events/sched_ext/sched_ext_dump/enable
echo D | sudo tee /proc/sysrq-trigger
sudo cat /sys/kernel/tracing/trace
```

---

## 5. Profiles

Three profiles are selectable at launch. `gaming` is an accepted alias for `default` — they select the exact same profile, not two separate configurations that happen to match.

| Profile | Base Quantum | New-Flow Bonus | Budgets T0 / T1 / T2 / T3 | Slices T0 / T1 / T2 / T3 |
| :--- | :--- | :--- | :--- | :--- |
| **Default** (`gaming`) | 2ms | 8ms | 1.5 / 8 / 20 / 100ms | 0.5 / 2 / 4 / 8ms |
| **Esports** | 1ms | 4ms | 1.5 / 4 / 20 / 50ms | 0.25 / 1 / 2 / 4ms |
| **Sim** | 4ms | 8ms | 3 / 8 / 80 / 200ms | 1 / 4 / 8 / 16ms |

Slices are the base quantum times the tier multiplier, which is the same on every profile: T0 0.25×, T1 1×, T2 2×, T3 ~4× (4095/1024). A task re-queued without a wakeup (slice expiry, preemption kick, yield) gets one base quantum, or its tier slice if that is shorter (T0); up to Gen 5 a re-queued T0 task got 4× its own slice. Up to Gen 4 the BPF side read compile-time copies of the quantum (2ms) and new-flow bonus (8ms), so Esports and Sim ran with Default's slices, re-queue slice, and new-flow bonus while their budgets did apply; Default was unaffected ([§11](#11-gen-5-changes)).

**Default** (also reachable as `--profile gaming`) is the scheduler-wide default — `sudo scx_imperator` with no flags runs this profile. It matches **Esports** exactly on the T0 and T2 budgets (1.5ms / 20ms): there's no reason to tolerate slower input/audio or render-thread latency on a desktop with CPU headroom to spare. Where Default differs from Esports is slice size and the T1/T3 budgets — Default uses double the base quantum and a double-length T3 budget, trading a larger worst-case margin for fewer context switches under normal, uncontended play. This profile requires no additional configuration on a desktop PC.

**Esports** tightens slice size and the T1/T3 budgets further than Default, at the cost of more context-switch overhead — use it when minimum worst-case latency matters more than raw throughput (e.g. a dedicated competitive-play machine). It is not strictly tighter than Default on every axis: T0/T2 budgets are tied between the two profiles.

**Sim** is designed for strategy, 4X, city-builder, and open-world games where a simulation or streaming thread is the dominant workload. It uses a 4ms quantum (reduces context-switch fragmentation on sustained T2/T3 work) and larger T2/T3 budgets (nothing latency-critical is competing with the sim thread). T1 matches Default exactly (8ms); T0 is proportionally — not literally — as protected as Default's, scaled to Sim's longer base quantum (a 3ms budget over a 1ms T0 slice is the same 3× margin as Default's 1.5ms over 0.5ms).

> [!NOTE]
> **Sim vs Default on FPS titles:** Sim's larger budgets widen the gaps between tiers: a queued T2 task can be passed by new T1 work for up to 72ms, and a T3 task by new T2 work for up to 120ms. On a pure FPS workload background tasks rarely saturate the CPU, so this is usually harmless, but the safe choice for competitive play remains **Esports** or **Default**.

The `--starvation` flag scales all tier budgets proportionally from the T3 base, preserving inter-tier ratios and therefore the tier order.

### DVFS Policy

Every tier on every profile requests `SCX_CPUPERF_ONE` (100% of hardware-permitted clock) through `scx_bpf_cpuperf_set()`; no frequency throttle is applied to background (T3) work the way earlier revisions did. The kernel feeds that request only to the schedutil governor (`sugov_get_util()`). Under `amd-pstate-epp` or `intel_pstate` in active mode there is no schedutil, the request has no effect, and frequency follows the driver's own EPP policy. Check which applies:

```bash
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_driver
```

`scx_imperator` targets desktop PCs on mains power; a laptop-style trade of CPU clock for battery or thermal headroom doesn't apply, and a throttled T3 task simply takes longer to finish a shader compile or background install for no benefit when the GPU is the actual bottleneck (the common case in nearly every game). What bounds T3's worst-case impact on foreground work is its deadline budget (§3), not frequency throttling.

---

## 6. Architecture

### Scheduler Flow

```
select_cpu
  ├── scx_bpf_select_cpu_dfl() finds an idle CPU (SCX_WAKE_SYNC placement is the kernel's)
  │     → hybrid: if the pick is an E-core, repeat the search from a P-core hint, keep it only if idle
  │     → direct dispatch via SCX_DSQ_LOCAL_ON with the task's own slice
  └── All busy → IRQ context (preempt count) or ksoftirqd waker? stamp CAKE_FLOW_IRQ_WAKE; return prev_cpu

enqueue
  ├── now = scx_bpf_now(), LLC = cpu_llc_id[task_cpu(p)]
  ├── kthread without ctx → queue with a T1 deadline
  ├── not a wakeup (slice expiry, kick, yield, new task) → own tier, fresh deadline,
  │     one-shot lock advance if it was switched out holding a lock, slice min(quantum, tier slice)
  ├── stamp enqueue_time for dispatch latency measurement
  ├── slept >500ms?       → move avg_runtime halfway to the tier midpoint (post-sleep recovery)
  ├── IRQ_WAKE flag       → tier = T0 (T2 for a T3 task; one-shot, consumed here)
  ├── Waker mailbox       → promote wakee tier if waker is higher priority (floor T1, T2 for T3 wakees)
  ├── New-flow / lock-boost flag → deadline advance, capped within the tier
  ├── vtime = now + tier budget - advance → insert into per-LLC DSQ
  └── T0/T1: claim a T3 (else T2) CPU in the LLC that the task may run on, not running a
        fresh lock holder and not already claimed → SCX_KICK_PREEMPT

dispatch
  ├── prev still runnable and its re-queue deadline ≤ head of the LLC DSQ (or a fresh lock
  │     holder, once) → keep running prev for another slice (not after sched_yield)
  ├── pull from local LLC DSQ
  └── if nothing runnable: steal from other LLCs (lowest ETD cost first, then index order)

running   → stamp last_run_at, update jitter_ewma_us from enqueue_time, release kick claim,
            publish tier to per-CPU mailbox, set tier bitmask
tick      → release a stale kick claim; past next_slice with work queued in the LLC or
            local DSQ → slice = 0 (reschedule, no self-IPI); mailbox + DVFS update
yield     → flag CAKE_XF_YIELDED, slice = 0
stopping  → clear tier bitmask (before reclassify); lock holder → one-shot lock boost if still
            runnable; real sleep (left TASK_RUNNING) → sleep stamp + cadence sample;
            reclassify: add the bout to the burst; EWMA on the burst (no promotion while still
            runnable); DRR++ deficit charged per bout; frame-cadence cap; next_slice recomputed
fexit/tp  → futex wait/lock return → lock holder + mailbox.lock_since; futex wake/unlock → clear
```

### Key Data Structures

| Structure | Size | Purpose |
| :--- | :--- | :--- |
| `imperator_task_ctx` | 64B (1 cache line) | Per-task EWMA state, tier, deficit, burst accumulator, sleep cadence, lock state, dispatch latency EWMA |
| `mega_mailbox_entry` | 64B (1 cache line) | Per-CPU tier broadcast for waker inheritance, DVFS cache, lock-holder timestamp |
| `imperator_stats` | 256B per CPU | Scheduler counters, summed by the loader |
| `kick_pending_mask` | 64B (1 cache line) | Bit per CPU with an outstanding preemption kick; claimed atomically by kickers |

### `imperator_task_ctx` Layout

| Bytes | Field | Purpose |
| :--- | :--- | :--- |
| 0–7 | `next_slice` | Time slice for next dispatch |
| 8–15 | `deficit_avg_fused` / `packed_info` | DRR++ deficit, avg_runtime, tier, stability, flags, one-shot extended flags |
| 16–19 | `last_run_at` | Timestamp of last dispatch start (or of the last kept-running decision) |
| 20–21 | `reclass_counter` | Graduated backoff counter |
| 22 | `overrun_count` | 8-bit shift register of per-sample overrun history |
| 23 | `lock_grace` | Slice extensions granted to a running lock holder this run (0 or 1) |
| 24 | `pending_futex_op` | Futex op recorded at syscall entry for the tracepoint fallback |
| 25–27 | `__align_pad` | Explicit alignment gap before u32 field |
| 28–31 | `enqueue_time` | Wall-clock ns at queue entry; consumed after one use |
| 32–33 | `jitter_ewma_us` | Per-task dispatch latency EWMA in ~µs |
| 34–35 | `cadence_us` | EWMA of the sleep-to-sleep period in ~µs (frame-cadence cap) |
| 36–39 | `sleep_entry_time` | Wall-clock ns at last real sleep; consumed by post-sleep recovery in `enqueue` |
| 40–41 | `burst_acc_us` | CPU time (~µs, saturating at 65535) summed across preempted bouts since the task last slept |
| 42–43 | `__pad16` | Reserved |
| 44–47 | `last_sleep_at` | Wall-clock ns of the previous real sleep (cadence sample origin) |
| 48–63 | `__pad` | Reserved |

---

## 7. Work Stealing & Topology

### ETD Calibration

On startup, calibration measures actual inter-core latency by pinning two threads to a CPU pair and exchanging a flag with atomic CAS, timed under real-time priority (`SCHED_FIFO` 99) for measurement accuracy. This runs in the background.

By default this doesn't measure every CPU pair. `select_etd_pairs()` samples 3 evenly-spread CPU pairs per LLC pair — enough for the cross-LLC cost table's per-LLC-pair `min()` reduction, since inter-core latency is dominated by which two physical domains a pair spans, not which specific cores within them. On single-LLC systems (single CCD/CCX — most current desktop parts) calibration is skipped entirely: nothing downstream ever reads a same-LLC latency value, so there's nothing worth measuring. This scoping exists specifically because two CPUs held under real-time priority is a real, if narrow, risk of colliding with an already-running game — the smaller and rarer that window, the better. `--full-etd-sweep` opts back into measuring every `C(nr_cpus, 2)` pair — full accuracy, full exposure — and logs an explicit warning stating the pair-count multiplier when used.

With exactly two LLCs (e.g. a 9950X) the steal scan has a single candidate, so the cost table never changes a decision. It orders steals on three or more LLCs (Zen 2 CCX parts, Threadripper).

| Parameter | Value |
| :--- | :--- |
| Round-trips per sample | 500 |
| Samples per pair | 50 |
| Warmup iterations | 200 |
| Max acceptable σ | 15 ns (3 retries) |

The **median** of samples is used (not the mean) to filter IRQ jitter. If affinity pinning fails for a pair, that entry is filled with a 500 ns sentinel so it is never treated as a free path. Until calibration completes (or on any system where it's skipped outright), cross-LLC stealing falls back to index order.

### Dispatch Order

Each LLC has its own dispatch queue, and a task is always queued on the LLC of the CPU it is assigned to (`task_cpu(p)`), on every enqueue path. On a task dispatch:

1. Try the calling CPU's local LLC first covers most dispatches with zero cross-LLC traffic
2. If nothing there can run on this CPU, build a steal mask of LLCs flagged non-empty and try the lowest-ETD-cost one first
3. Fall through remaining LLCs in order

An LLC's non-empty flag is cleared only when its queue is actually empty, not when a pull fails because every queued task is pinned to other CPUs. There is no minimum queue depth for stealing: the `threads_per_ccd` gate, which waited for 16 queued tasks on a 9950X, was removed in Gen 5.

On single-LLC systems the steal path is eliminated entirely at load time: `nr_llcs` is a frozen rodata value, so the verifier resolves the branch and drops the dead side.

### Hybrid P/E-Core Steering

On systems with Performance/Efficiency core asymmetry (`has_hybrid` set by topology detection), the idle-CPU path in `select_cpu` doesn't stop at an E-core pick from the kernel's default idle search. It scans the P-cores the task may run on, in index order, and takes the first one whose physical core has no SMT sibling, falling back to the first allowed P-core. The scan itself doesn't test idleness. It only produces a *hint*: the kernel's idle search is repeated from that CPU, and its result is used only if the kernel reports it idle. The result can be any idle CPU the kernel finds from that starting point, not necessarily the hinted P-core. No effect on non-hybrid systems.

This path was compiled out up to Gen 4 (see [§11](#11-gen-5-changes)); its known issues are listed in [§10](#10-known-limitations).

### Preemption Kick

When a T0 or T1 task is queued while every CPU is busy, a victim CPU in the same LLC is kicked immediately: a CPU running a T3 task, or failing that one running a T2 task. Candidates are walked lowest index first, up to 8 per tier, and a CPU is taken only if:

- the queued task is allowed to run there (a single-CPU task only considers its own CPU);
- it is not running a lock holder inside its protection window (§4);
- no other enqueue has claimed it yet — claims are an atomic fetch-OR on `kick_pending_mask`, released by the victim when it switches tasks or at its next tick.

Up to Gen 5 the victim was always the lowest-numbered T3 (else T2) CPU: a burst of T0/T1 wakeups kicked the same CPU over and over, and a pinned or affinitized task (per-CPU kworkers, Wine threads with an affinity mask) kicked a CPU it could not run on. LAVD gets distinct victims the same way, by CAS-ing the victim's estimated stop time.

T0 and T1 CPUs are never kicked to run another latency-critical task, and T2/T3 enqueues never kick (A/B testing showed a 1% low regression). Up to Gen 4 the candidate mask was built from the compile-time `nr_cpus = 8`, so CPUs 8 and above were never kicked.

### Slice Expiry

`ops.dispatch` runs before the kernel re-queues a task whose slice ended. If that task is still runnable, the deadline it would get on re-queue (now + its tier budget) is compared with the head of its LLC queue; if it is no later, the task keeps the CPU for another slice and its finished segment is folded into its burst. Up to Gen 5 the queue head always won, so a T2 render thread past its 4ms slice handed the CPU to a T3 task that had queued a moment earlier and then waited behind it. Tasks that called `sched_yield()` are never kept (`ops.yield` flags them), and when the local queue is empty the old behaviour applies (steal across LLCs, else the kernel keeps the task on a default slice).

The tick only ends a slice when work is queued for the LLC, and does so by setting the slice to 0 (LAVD's `preempt_at_tick()`), which makes the kernel reschedule without a self-IPI.

---

## 8. Overhead

> [!NOTE]
> The figures below were measured against an earlier revision and have not been re-profiled since. Several features added later in this scheduler's history (ETD-aware steal ordering, the M-2 mailbox-consistency fix, the post-sleep recovery check moving from `stopping` to `enqueue`, and every Gen 5 and Gen 6 change) touch the functions listed here; the notes column records what changed, but the numbers do not reflect it. Treat this table as directionally useful, not as a current measurement.

The added cost relative to a minimal sched_ext skeleton is approximately 20%, concentrated in `select_cpu` and `enqueue`. The cycle counts below predate the ETD-aware steal-ordering feature in `dispatch` (see [§7](#7-work-stealing--topology)) and have not been re-measured since; treat the `dispatch` row as **not current** rather than as a measured zero.

| Function | Added cost | Notes |
| :--- | :--- | :--- |
| `select_cpu` | ~2 cycles | Task storage fetched on the idle path (slice) and on IRQ-context wakeups. Gen 5 removed the SYNC fast path and the scratch writes on the all-busy path; Gen 6 reads the per-CPU preempt count on the all-busy path |
| `enqueue` | +6 cycles steady-state | Mailbox read is the baseline cost. Gen 5 adds `scx_bpf_now()` and `scx_bpf_task_cpu()` calls. Gen 6: a T0/T1 kick reads `kick_pending_mask`, tests the task's cpumask per candidate and claims the victim with one atomic fetch-OR |
| `dispatch` | *unmeasured since ETD-steal was added* | Local-LLC-empty path computes a cheapest-cost candidate across LLCs before falling back to index order. Gen 5 adds one `scx_bpf_dsq_nr_queued()` read when a pull fails. Gen 6: when the previous task is still runnable, one task-storage lookup and a DSQ peek |
| `tick` | +2 cycles | Up to two `scx_bpf_dsq_nr_queued()` reads once the running task passes `next_slice`. Gen 6 removes the unreachable Phase 2 (and its `scx_bpf_cpu_rq()` call, a kfunc now deprecated upstream) and ends the slice without a self-IPI |
| `running` | +11 cycles | Mailbox write + tier bitmask set + jitter EWMA update (idle-path dispatch: +2 cycles — guard branch only) |
| `stopping` | +5 cycles | Tier bitmask clear, burst accumulator. Gen 6 adds the sleep/cadence bookkeeping and the one-shot flag cleanup |
| lock probes | fexit, per futex call | One task-storage lookup and a mailbox store on a lock acquire or release; nothing otherwise. `--lock-boost off` detaches them |

All per-task fields sit on the same 64B cache line as `last_run_at` and `next_slice`.

With telemetry off, the verifier sees the frozen `enable_stats = false` and drops the counter code at load time. To measure the current per-call cost of every callback on a running system (mean ns per call over 10 seconds):

```bash
sudo sysctl -qw kernel.bpf_stats_enabled=1 && sleep 10 && sudo bpftool prog show | awk '/ name imperator_/ {n=""; t=0; c=0; for (i=1;i<=NF;i++) {if ($i=="name") n=$(i+1); if ($i=="run_time_ns") t=$(i+1); if ($i=="run_cnt") c=$(i+1)} if (c) printf "%-16s %8.1f ns/call %12d calls\n", n, t/c, c}'; sudo sysctl -qw kernel.bpf_stats_enabled=0
```

---

## 9. Vocabulary

### Core Concepts

| Term | Definition |
| :--- | :--- |
| **EWMA** | Exponentially Weighted Moving Average. Tracks each task's burst length with asymmetric decay promotions converge in ~4 samples, demotions in ~16. |
| **Burst** | CPU time a task uses between waking and sleeping, summed across preemptions. The EWMA's input since Gen 5. |
| **Tier** | Classification level (T0–T3) by avg_runtime. Controls slice size, deadline budget, and preemption-kick eligibility. |
| **Deficit** | Per-task credit from DRR++. New tasks get bonus credit; exhaustion removes the bonus and the task competes normally. |
| **Quantum** | Base time slice allotted before a scheduling decision. Scaled by tier multiplier. |
| **Deadline Budget** | Per-tier offset added to a task's enqueue time to form its queue deadline. Budgets rise with tier, so same-time arrivals keep tier order, and the gap between two budgets is the longest a waiting task can be passed by newer higher-tier work. Set per profile; scaled by `--starvation` (the flag keeps its old name). |
| **DRR++** | Deficit Round Robin++. Network CAKE flow-fairness algorithm adapted for CPU task scheduling. |
| **Jitter** | Variance in scheduling latency between consecutive events. Low jitter = consistent frame delivery. |
| **Dispatch Latency** | Time between a task entering the dispatch queue and actually running. Tracked per-task as `jitter_ewma_us`; mean shown live in TUI summary bar. |
| **Cadence** | EWMA of a task's sleep-to-sleep period. A short cadence with idle time in each period marks a frame-paced thread, which is held at T2 (§3). |
| **Lock Holder** | A task that returned from a futex wait/lock in its current run and has not called futex wake/unlock. Protected from preemption for a short window (§4). |
| **kns** | Kilonanoseconds — nanoseconds divided by 1024 (right-shift by 10). Internal unit used for the deficit and the packed tier config to keep values in u16 range. |

### Architecture

| Term | Definition |
| :--- | :--- |
| **Fused Config** | 3 parameters packed into one 64-bit word: `[mult:12][quantum:16][starve:20]`, with 16 bits reserved. A `budget` field previously occupied bits 28–43 but was never read by any scheduling decision; it was removed and `starve` repacked down into the freed range rather than leaving a gap. `starve` holds the tier's deadline budget. |
| **Mega-Mailbox** | 64B per-CPU cache-line-isolated state. Carries tier information for waker inheritance, the DVFS cache and the lock-holder timestamp, each written only by its own CPU. |
| **Graduated Backoff** | Confidence system that reduces reclassification frequency once a task's tier has been stable for 3+ stops. |
| **Vtime** | The DSQ sort key: `enqueue time + tier budget - capped advance`. Encodes both priority and arrival order. |
| **Bit-History Register** | 8-bit shift register tracking per-sample overrun outcomes. A one-tier demotion triggers when 4 of the last 8 samples exceeded 1.5× the tier gate. |
| **RODATA** | Globals the loader writes before load (`quantum_ns`, `nr_cpus`, `tier_configs`, ...). They must be `const volatile`; a plain `const` is folded to its initializer by clang and the loader's value never reaches the code. |

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
| Lock-holder detection and protection | scx_lavd (`lock.bpf.c`, `is_lock_holder_running()`, `consume_prev()`), bounded by a time window |
| Burst-since-last-sleep classification | scx_lavd (`acc_runtime`; `max(avg_runtime, acc_runtime)` in `calc_sum_runtime_factor()`) |
| Frame-cadence cap | scx_lavd (`wait_freq` in `calc_lat_cri()`; sleep-only sampling as in `lavd_quiescent()`) |
| IRQ-context detection via preempt count | scx `bpf_experimental.h`, as used by scx_lavd |
| Distinct preemption victims, affinity-aware victim search | scx_lavd (`find_victim_cpu()`, `ask_cpu_yield_after()`) |
| Keep the expiring task when it is still most urgent | scx_lavd `consume_prev()` / scx_bpfland |
| Slice-zero preemption at tick | scx_lavd (`preempt_at_tick()`) |
| Per-tier deadline ordering | Original (Gen 5) — replaces strict tier priority with bounded waiting while keeping tier order for same-time arrivals |
| Dispatch latency telemetry (`jitter_ewma_us`) | Original — closes the per-task jitter measurement gap |
| ETD-aware steal ordering (cheapest-LLC-first) | Original — extends ETD calibration from a fallback-avoidance signal into an active steal-ordering input |
| Desktop-first DVFS policy (no T3 throttle, deadline-bounded instead) | Original — replaces frequency throttling with deadline budgets as the mechanism bounding background-task impact |

---

## 10. Known Limitations

| Area | Current behavior |
| :--- | :--- |
| **IRQ-wake scope** | Timer expirations are hardirq wakeups (§4), so every task waking from a timed sleep gets a one-dispatch boost, background tasks included. The T3→T2 cap keeps bulk tasks from preempting anything. Until Gen 6 this boost was effectively off (§12), so the project's earlier A/B results were measured without it; `--no-irq-boost` restores that behavior. |
| **Lock-holder detection** | Keyed on futex return values, so condvar and job-queue waiters are flagged too; the protection window bounds the effect. Uncontended locks are invisible (§4). |
| **Frame-cadence cap** | A periodic background job with the same shape as a game thread (sleeps ≥ 30 times a second, idle part of each period, bursts over 8ms) is also held at T2. |
| **Waker inheritance on 6.12–6.14** | Wakelist-delivered wakeups read the target CPU's mailbox (§4). |
| **Victim choice** | Within a tier, candidates are still tried lowest index first; distinct victims come from the claim mask, not from comparing what each CPU is running. |
| **Hybrid steering** | The first idle search has already claimed an E-core's idle bit; when the P-core retry succeeds, that E-core stays marked busy until it next passes through idle. The P-core scan doesn't check idleness (§7). |
| **Nice changes** | Read once per task (§3). |
| **DVFS** | Every tier targets `SCX_CPUPERF_ONE`; the request only reaches the schedutil governor (§5). |
| **CPU count** | Per-CPU arrays hold 64 entries and CPU indices are masked with `& 63`; nothing refuses to load on larger systems. |
| **Build** | With clang 21, `bpf_compat.h`'s `__atomic_load_n` path needs `-mcpu=v4`; `-mcpu=v3` fails in instruction selection. |
| **Validation** | Gen 6 was verified by loading it under the kernel verifier and running a synthetic gaming workload in a QEMU/KVM guest of a 7.2 kernel (1 and 2 LLCs). It has not been A/B tested in real games. |

---

## 11. Gen 5 Changes

| Change | Reason |
| :--- | :--- |
| `enqueue` reads `scx_bpf_now()` and the LLC of `task_cpu(p)` itself | The time and LLC tunneled from `select_cpu` were stale on every enqueue with no same-CPU `select_cpu` before it: slice expiry, kicks, yields, pinned-task wakeups, and (before 6.15) wakelist wakeups. Re-queued tasks carried old or zero timestamps and jumped ahead of fresh wakeups in their tier. |
| `tick` kicks only when a task is queued | With nothing queued the kernel keeps the task running and refills its slice without `ops.stopping`/`ops.running`, so the old unconditional kick fired on every tick. |
| Non-empty flag cleared only when the queue is empty; `threads_per_ccd` steal gate removed | The flag was cleared whenever a pull failed; the gate refused to steal until 16 tasks were waiting on a 9950X. |
| SYNC wakeups left to `scx_bpf_select_cpu_dfl()`; `dispatch_sync_cold()` removed | The fast path stacked every SYNC wakee on the busy waker's local DSQ, ahead of tier order. |
| `wake_flags` no longer passed as `enq_flags` | On 6.12–6.18, `WF_SYNC` and `ENQUEUE_HEAD` are both 0x10, so SYNC wakees were inserted at the head of the local DSQ. |
| Deadline ordering (`tier_deadline()`) | Strict tier priority could leave a queued T3 task waiting until the sched_ext watchdog disabled the scheduler (§3). |
| Classification on burst since last sleep (`burst_acc_us`) | Per-bout samples measured the scheduler's own slice under contention: CPU-bound tasks drifted to T2 and render threads flipped between T1 and T2 (§3). |
| `barrier_var()` on both `tier_configs` indices in `tier_deadline()` | Clang dropped the `& 7` mask on `t - 1` because it knew `t ∈ [1,3]`; the verifier tracked that test on a different register copy and rejected the load ("R5 unbounded memory access"). |
| 15 loader-written globals made `const volatile` | As plain `const` globals they were constant-folded, so the loader's values never reached the BPF code. |

Effects of the `const volatile` change, which was hidden behind the folding:

- `--stats` and the TUI receive data; before, every counter stayed at zero
- T0/T1 kicks can target every CPU in the LLC; before, only CPUs 0–7
- On multi-CCD systems, per-LLC queues and cross-LLC stealing run for the first time; before, all CPUs shared one queue
- On Intel hybrid systems, P-core steering runs for the first time
- Esports and Sim use their own quantum and new-flow bonus; `--quantum` and `--new-flow-bonus` take effect

---

## 12. Gen 6 Changes

Gen 6 re-read scx_lavd against IMPERATOR's features and scx_cake against what IMPERATOR had removed. Nothing removed from CAKE was worth restoring: the SYNC fast path, the `select_cpu`→`enqueue` value tunnel and the T3 frequency throttle were each removed for a documented correctness or desktop-policy reason. The changes below come from LAVD, or fix features that had silently not run.

| Change | Reason |
| :--- | :--- |
| IRQ context read from the per-CPU preempt count (`bpf_compat.h`) | `bpf_in_hardirq()`/`bpf_in_nmi()`/`bpf_in_serving_softirq()` were declared as weak kfuncs; no kernel exports them, so they were NULL and the IRQ-wake boost fired only for ksoftirqd wakeups (1 boost in 60s in a VM test vs ~12,000/s after the fix) |
| IRQ and waker boosts lift a T3 task to T2 at most; IRQ flag stamped only on the all-busy path | A bulk task woken by a disk or timer interrupt jumped to T0 and kicked a T2 (render) CPU; on the idle path the boost only shrank the task's slice to the T0 slice |
| Lock-holder protection compiled, attached and bounded (`lock.bpf.c`, `--lock-boost`) | `lock.bpf.c` was never built; its tracepoint structs were also misaligned. Now: fexit probes (tracepoint fallback), `futex_waitv` covered, protection limited to a quarter-quantum window, cleared at every stop |
| Preemption victims claimed through `kick_pending_mask`, filtered by the task's cpumask, lock holders skipped | Bursts of T0/T1 wakeups all kicked the lowest-numbered T3 CPU; pinned/affinitized tasks kicked CPUs they could not run on |
| `ops.dispatch` keeps an expiring task when its re-queue deadline is no later than the LLC queue head; `ops.yield` added | The queue head always won at slice expiry, even a T3 task over a T2 one; yields stay honoured |
| Tick ends a slice by zeroing it; Phase 2 starvation check removed | Phase 2 could never fire (budgets exceed slices); the self-kick was an irq_work IPI; its `scx_bpf_cpu_rq()` use is deprecated upstream |
| Sleep = left `TASK_RUNNING`, not `runnable == false` | `ops.stopping(p, false)` also fires on property-change dequeues; each one ended the burst, so CPU spinners sat in T2 |
| Frame-cadence cap | CPU-heavy frame-paced threads (main thread > 8ms per frame) classified as T3 |
| Re-queue slice `min(quantum, tier slice)` | A re-queued T0 task got 4× its own slice |
| Burst credit, `sim_mode`, dead `init_task` branches removed | Never ran: credit keyed on `SCX_ENQ_PREEMPT`, which `ops.enqueue` never receives; task storage did not exist yet in `init_task` |
| `ops.dump_task` | Per-task tier/burst/cadence line in the sched_ext debug dump |
| Headless loop checks for a BPF-side exit every second | It checked only every 60 seconds |
| Stats: `nr_tick_preempts_tier`, `nr_preempt_kicks`, `nr_prev_kept`, `nr_lock_holder_protects`, `nr_cadence_caps` | Replace counters that could not move (`nr_starvation_preempts_tier`, `nr_lock_holder_skips`, burst-credit counters); requeues now count as "old flow" dispatches |

Tried and dropped: re-queuing a kicked task at its original deadline. Under frequent kicks a CPU hog was kicked before its slice ended over and over, never received a fresh deadline, and ended up sorting ahead of the frame thread (frame-wake p50 rose from ~0.3ms to ~1.2ms in the VM test). Doing it correctly needs remaining-slice accounting.

### Validation

Loaded under the kernel verifier and run as root in a QEMU/KVM guest booting the host's 7.2 kernel, with a synthetic workload: 10 CPU hogs on 8 vCPUs, a 60 fps main thread spending 10ms per frame, a render thread handed work by condvar, an audio-like 2ms timer thread, mutex contention, `sched_yield` spinners, `futex_waitv` ping-pong and fork churn. Numbers from a VM sharing 8 host CPUs are noisy and are not a substitute for in-game A/B testing.

| Metric (1 LLC, 60s) | Gen 5 | Gen 6 | Gen 6 `--no-irq-boost` |
| :--- | :--- | :--- | :--- |
| Frame-thread wake latency p50 / p90 / p99 | 310 / 1299 / 9015 µs | 99 / 687 / 3762 µs | 288 / 970 / 3394 µs |
| Render handoff p90 / p99 | 872 / 10532 µs | 471 / 5748 µs | 596 / 6059 µs |
| Frames overrunning their 16.7ms period | 55 | 23 | 24 |
| Audio-thread wake p99 | 1949 µs | 1571 µs | 1757 µs |

The `--no-irq-boost` column isolates the classification and dispatch changes (burst/sleep fix, frame-cadence cap, keep-running dispatch, victim claiming): they account for most of the tail and missed-frame improvement, and the IRQ boost mostly cuts median frame-thread wake latency.

On two LLCs (2 sockets × 4 cores), frame-thread wake p50/p90 went from 281/1289 µs to 99/642 µs and overrunning frames from 83 to 45. The scheduler stayed enabled through every run; ETD calibration and the LLC cost table worked on the two-LLC guest.

