## **I.M.P.E.R.A.T.O.R**

**IRQ-Aware · Multitiered · Preemptive · EWMA · Relayed · Aging · Topology · Overrun · Runtime**

| | Word | What it refers to |
| :--- | :--- | :--- |
| **I** | IRQ-Aware | Wakeups from hardware interrupts, softirqs, ksoftirqd and timers run at T0 for one dispatch (§4) |
| **M** | Multitiered | Four tiers, T0 Critical to T3 Bulk (§3) |
| **P** | Preemptive | A queued T0/T1 wakeup kicks the lowest-numbered T3 (else T2) CPU in its LLC; a task past its slice is kicked when work is waiting (§6, §7) |
| **E** | EWMA | Tier comes from an asymmetric moving average: promotions settle in ~4 samples, demotions in ~16 (§3) |
| **R** | Relayed | On a queued wakeup, the waker's tier is relayed to the task it wakes, floored at T1, for that dispatch (§4) |
| **A** | Aging | Queue order is enqueue time plus a per-tier budget, so a waiting task overtakes newer higher-tier work once it has waited out the gap (§3) |
| **T** | Topology | Per-LLC queues, ETD-ordered cross-LLC stealing, hybrid P/E-core steering (§7) |
| **O** | Overrun | 4 of the last 8 samples over 1.5× the tier gate drops a task one tier (§3) |
| **R** | Runtime | Classification input is observed CPU time between waking and sleeping (§3) |

> **ABSTRACT**: `scx_imperator` is a BPF CPU scheduler built on [sched_ext](https://github.com/sched-ext/scx), designed for **gaming workloads** on modern AMD and Intel hardware. It classifies every task by observed runtime behavior and routes work through a 4-tier priority system high-priority tasks like audio callbacks and mouse input get CPU time first, bulk work like compilers gets it last.
>
> - **4-Tier Classification** Tasks sorted by an asymmetric EWMA of burst length (CPU time between waking and sleeping) into Critical / Interactive / Frame / Bulk
> - **Deadline-Bounded Priority** Each queued task is keyed by its enqueue time plus a per-tier budget: tasks that arrive together run in strict tier order, and a task that has waited out its budget gap goes ahead of newer higher-tier work, so no tier starves
> - **IRQ-Wake Boosting** Wakeups from hardware interrupts and timers (GPU vsync, audio DMA, network, timed sleeps) promote that task to T0 for one dispatch
> - **Waker Tier Inheritance** High-priority task waking a lower-priority one lifts the wakee's tier, keeping producer-consumer chains tight
> - **ETD Calibration** Startup CAS ping-pong measures actual inter-core latency; on systems with three or more LLCs, cross-LLC work stealing tries the empirically-cheapest LLC first, falling back to index order before calibration completes
> - **Hybrid P/E-Core Steering** On Intel hybrid systems, when the kernel's idle pick is an Efficiency core, the idle path repeats the kernel's idle search from a Performance-core hint and uses the result only if the kernel reports it idle
> - **Dispatch Latency Telemetry** Every queued task tracks its own scheduling latency (enqueue-to-run) as a per-task EWMA; mean dispatch latency is shown live in the TUI summary bar and clipboard export, or logged periodically in headless mode via `--stats`
> - **Desktop-First DVFS** Every tier requests full CPU clock; no power-saving throttle on background work, since `scx_imperator` targets mains-powered desktops. The request only takes effect under the schedutil governor (§5)
>
> Lock-holder protection and preemption burst credit are implemented but inactive in this build; §4 explains why.

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

---

## 1. Quick Start

```bash
# Prerequisites: Linux Kernel 6.12+ with sched_ext, Rust toolchain

# Clone and build
git clone https://github.com/Michael-Sebero/SCX-IMPERATOR
cd SCX-IMPERATOR && cargo build --release

# Install
sudo install -m 755 target/release/scx_imperator /bin/scx_imperator

# Run (requires root) — uses the Default profile, tuned for desktop gaming
sudo scx_imperator

# Competitive/esports profile — tightest worst-case latency, more context-switch overhead
sudo scx_imperator -p esports

# Headless telemetry: logs a stats summary roughly every 60 seconds
sudo scx_imperator -s
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
> Game render threads with 2–8ms of CPU per frame classify as T2, physics/AI at 0.5–2ms as T1, input handlers under 100µs as T0. A thread lands in T3 when it runs 8ms or more between sleeps: shader compilation, loading screens, and a main thread that needs more than 8ms of CPU per frame (a known limitation, see [§10](#10-known-limitations)).

### How Classification Works

1. **Initial placement**: Based on `nice` value `nice < 0` → T0, `nice 0–10` → T1, `nice > 10` → T3. Kthreads at nice 0 start at T1, not T0. The nice value is read once, when the scheduler first sees the task; renicing a running task does not reseed its tier.
2. **Runtime seeding**: avg_runtime is seeded at the midpoint of the initial tier's expected range (T0 50µs, T1 1050µs, T3 8001µs), not zero. Starting from zero lets any task with a short first bout masquerade as T0 for several windows.
3. **Burst accounting**: The sample fed to the EWMA is CPU time summed from the moment a task wakes until it sleeps, across any preemptions in between (`burst_acc_us`). While a burst is still in progress (the task was preempted, not blocked), its running total is a lower bound, so it can only raise the average; promotion waits until the task actually sleeps. Up to Gen 4 each preempted bout was sampled on its own, and a preempted bout ends at the scheduler's own slice boundary, so under contention every CPU-bound task drifted to T2.
4. **EWMA authority**: After ~4 bursts, the EWMA avg_runtime becomes authoritative. A nice -5 task that runs 50ms bursts reclassifies to T3 regardless of nice value.
5. **Asymmetric convergence**: Promotions (shorter runtime) converge in ~4 samples (α = 1/4); demotions (longer runtime) take ~16 (α = 1/16). Hysteresis gates stop oscillation at the boundaries: promotion requires the average to fall below 90% of the gate (90µs / 1800µs / 7200µs).
6. **Overrun demotion**: On each full reclassification pass, an 8-bit shift register records whether the sample exceeded 1.5× the tier gate (150µs / 3ms / 12ms, T0–T2). When 4 of the last 8 recorded samples did, the task drops one tier. An average above 24ms with a stable tier forces T3 outright.
7. **Graduated backoff**: Once a task's tier has been stable for 3 consecutive stops, the full reclassification path slows: T0 every 1024th stop, T1 every 128th, T2 every 32nd, T3 every 16th. The EWMA still updates every stop, and a spot check resets the backoff as soon as the new average would cross a gate.
8. **Post-sleep recovery**: When a task wakes after sleeping more than 500ms and is queued because no CPU is idle, its average is moved halfway toward the midpoint of its current tier (50µs / 1050µs / 5000µs / 8001µs) before it is queued, so a thread that spent a loading screen at T3 doesn't need 10+ bursts to recover. Wakeups placed directly on an idle CPU skip this step.
9. **Fork and exec**: Every new task, forked threads included, is seeded from its own nice value. The fork-inheritance and exec-reset branches in `imperator_init_task` never run: task storage is created in `ops.enable`, which runs after `init_task`, and sched_ext has no exec hook, so classification carries across `exec`.

### DRR++ Deficit Tracking

Adapted from network CAKE's flow fairness algorithm:

- Each task starts with a **deficit** of quantum + new-flow bonus (10ms on the Default profile)
- Each execution bout consumes deficit proportional to runtime
- While deficit remains, the task's queue deadline is advanced by the new-flow bonus (8ms on Default); for T1–T3 the advance is capped just below the gap to the next tier's budget, so it only reorders a task within its own tier
- When deficit exhausts → new-flow bonus removed → task competes normally

The bonus applies from a task's first wakeup onward. A brand-new task's very first enqueue is not a wakeup: if no CPU is idle it is queued at its seeded tier without the advance.

---

## 4. Context Signals

These features act on top of the base tier system. Three are active: IRQ-wake boost, waker tier inheritance, and dispatch latency telemetry. Two are implemented but inactive in this build: lock-holder protection and preemption burst credit. None of them modify a task's permanent classification — they affect one dispatch or one queue position at a time.

### IRQ-Wake Boost

When a wakeup originates from a hardware interrupt, NMI, softirq, or ksoftirqd, the woken task runs at T0 for that one dispatch. The flag is consumed immediately. This matters because a task woken by a mouse click or audio DMA completion may not yet have a T0 EWMA history the hardware urgency shouldn't wait for behavioral evidence to accumulate.

Timer expirations count as interrupts. On non-PREEMPT_RT kernels, hrtimer sleepers (`nanosleep`, futex/poll/epoll timeouts) expire in hardirq context, so any task waking from a timed sleep is boosted the same way. That covers sleep-based frame limiters, and also any background task that wakes on a timer. On the idle path the boosted task gets the T0 slice. When all CPUs are busy it is queued with a T0 deadline, which kicks a T3 or T2 victim, but it keeps its own tier's slice.

### Waker Tier Inheritance

On queued wakeups (all CPUs busy), the woken task's tier is compared against the tier of the CPU that woke it (read from a per-CPU mailbox updated on every context switch). If the waker's tier is lower-numbered (higher priority), the wakee is promoted to match it, floored at T1. A T0 audio thread waking a T2 event dispatcher promotes it to T1 for that dispatch. The promotion changes queue order and kick eligibility; the slice stays the wakee's own.

On 6.15+ kernels, `ops.enqueue` for a wakeup runs on the waker's CPU, so the mailbox read is the waker's tier. On 6.12–6.14, wakeups delivered through the ttwu wakelist run `ops.enqueue` on the target CPU and read that CPU's mailbox instead.

### Lock-Holder Protection

**Inactive in this build.** Every program in `lock.bpf.c` is declared `SEC("?fexit/...")` or `SEC("?tracepoint/...")`, which libbpf does not auto-load, and the loader only calls `attach_struct_ops()`. `CAKE_FLAG_LOCK_HOLDER` is therefore never set. To check a running system (0 means not loaded):

```bash
sudo bpftool prog show | grep -c imperator_fexit
```

What the flag does when the probes are loaded:

1. The holder's queue deadline is advanced by the new-flow bonus, capped within its tier as described in §3, so it sorts ahead of same-tier tasks and releases the lock sooner
2. A tick-side starvation skip (up to 4 consecutive skips) is coded in Phase 2 of `imperator_tick`, which cannot fire: every profile's budget is longer than its slice, so a task past its budget is also past its slice, and when anything is queued the slice check kicks and returns first

Known issues to fix before enabling it: `futex_wait` returning 0 means the task was woken, not that it owns a lock, so condvar and job-queue waiters get flagged too; the flag clears only when the task itself calls `futex_wake` (LAVD clears its futex boost at every `ops.stopping`); `futex_waitv`, which Proton's fsync uses, isn't hooked.

> [!NOTE]
> **Coverage gaps**: Uncontended locks never enter the kernel and are invisible to this path. `FUTEX_CMP_REQUEUE_PI` (glibc condvar + PI-mutex, `PTHREAD_MUTEX_PRIO_INHERIT`) *is* covered, not skipped — `FUTEX_WAIT_REQUEUE_PI` doesn't return to userspace until the waiter actually owns the lock, and the existing fexit probe fires on exactly that return. The real gap is narrower: the flag is set when the waiter's own syscall returns, not at the instant the kernel transfers ownership during the waker's requeue call, so it can lag true ownership by up to one scheduling round-trip. Closing that fully would mean hooking an internal, per-waiter kernel function with a documented history of subtle correctness bugs in this exact code path — left as a known, narrow, fail-safe timing gap rather than a guessed-at hook into unstable internals.

### Dispatch Latency Telemetry

Every task records a timestamp when it enters the dispatch queue (`enqueue_time`) and measures how long it waited before actually running. This per-task dispatch latency is tracked as an α=1/8 EWMA stored in `jitter_ewma_us` — the first per-task scheduling jitter signal in the scheduler.

Each context switch accumulates the current EWMA sample into two per-CPU counters (`nr_jitter_ewma_sum`, `nr_jitter_ewma_count`) in `imperator_stats`. The TUI aggregates these across all CPUs and displays the mean dispatch latency live in the summary bar (`Dispatch latency: Xµs`) and in the clipboard export under `C2-Infra Dispatch latency telemetry`.

Collection (`enable_stats`) is switched on by `-s`/`--stats` or by the TUI (`-v`/`--verbose`). With `--stats`, a summary line including mean dispatch latency is logged roughly every 60 seconds, and the raw per-CPU counters remain readable via `bpftool map dump` on the scheduler's `bss` map. `--stats` is implied by `--verbose` and harmless (redundant) alongside it. Up to Gen 4, `enable_stats` was a plain `const` that clang folded to `false`, so every counter stayed at zero whatever the flags ([§11](#11-gen-5-changes)).

Tasks placed directly on an idle CPU from `select_cpu` never enter the queue and have no wait to record, so they aren't sampled. That includes SYNC wakeups the kernel places on an idle CPU. Per-task state starts at zero when the scheduler first sees a task.

### Preemption Burst Credit

**Inactive in this build.** Credit is earned only when `ops.enqueue` sees `SCX_ENQ_PREEMPT`, and the kernel never passes it there: a preempted task is re-enqueued by `put_prev_task_scx()` with `0` or `SCX_ENQ_LAST`, and `SCX_ENQ_PREEMPT` exists only as an input flag for `scx_bpf_dsq_insert()` on local DSQs. Those re-enqueues also take the non-wakeup path, which returns before the credit logic. `burst_credit[earned=0 consumed=0]` in the `--stats` line confirms it.

As designed, T1 (Interactive) and T2 (Frame) tasks preempted before completing their slice would earn roughly one quarter of a quantum of credit per preemption, up to a per-tier cap, consumed on the same re-enqueue to extend the slice:

| Tier | Cap (Default/Esports) | Cap (Sim profile) | Approx. max bonus |
| :--- | :--- | :--- | :--- |
| T0 Critical | none | none | — |
| T1 Interactive | 2000 kns | 2000 kns | ~2ms |
| T2 Frame | 4000 kns | 4000 kns | ~4ms |
| T3 Bulk | none | 1000 kns | Sim only: ~1ms |

T0 is excluded on every profile; T3 is excluded everywhere except Sim, where the simulation thread itself may be the T3 task that matters.

---

## 5. Profiles

Three profiles are selectable at launch. `gaming` is an accepted alias for `default` — they select the exact same profile, not two separate configurations that happen to match.

| Profile | Base Quantum | New-Flow Bonus | Budgets T0 / T1 / T2 / T3 | Slices T0 / T1 / T2 / T3 |
| :--- | :--- | :--- | :--- | :--- |
| **Default** (`gaming`) | 2ms | 8ms | 1.5 / 8 / 20 / 100ms | 0.5 / 2 / 4 / 8ms |
| **Esports** | 1ms | 4ms | 1.5 / 4 / 20 / 50ms | 0.25 / 1 / 2 / 4ms |
| **Sim** | 4ms | 8ms | 3 / 8 / 80 / 200ms | 1 / 4 / 8 / 16ms |

Slices are the base quantum times the tier multiplier, which is the same on every profile: T0 0.25×, T1 1×, T2 2×, T3 ~4× (4095/1024). A task re-queued after preemption gets one base quantum regardless of tier. Up to Gen 4 the BPF side read compile-time copies of the quantum (2ms) and new-flow bonus (8ms), so Esports and Sim ran with Default's slices, re-queue slice, and new-flow bonus while their budgets did apply; Default was unaffected ([§11](#11-gen-5-changes)).

**Default** (also reachable as `--profile gaming`) is the scheduler-wide default — `sudo scx_imperator` with no flags runs this profile. It matches **Esports** exactly on the T0 and T2 budgets (1.5ms / 20ms): there's no reason to tolerate slower input/audio or render-thread latency on a desktop with CPU headroom to spare. Where Default differs from Esports is slice size and the T1/T3 budgets — Default uses double the base quantum and a double-length T3 budget, trading a larger worst-case margin for fewer context switches under normal, uncontended play. This profile requires no additional configuration on a desktop PC.

**Esports** tightens slice size and the T1/T3 budgets further than Default, at the cost of more context-switch overhead — use it when minimum worst-case latency matters more than raw throughput (e.g. a dedicated competitive-play machine). It is not strictly tighter than Default on every axis: T0/T2 budgets are tied between the two profiles.

**Sim** is designed for strategy, 4X, city-builder, and open-world games where a simulation or streaming thread is the dominant workload. It uses a 4ms quantum (reduces context-switch fragmentation on sustained T2/T3 work) and larger T2/T3 budgets (nothing latency-critical is competing with the sim thread). T1 matches Default exactly (8ms); T0 is proportionally — not literally — as protected as Default's, scaled to Sim's longer base quantum (a 3ms budget over a 1ms T0 slice is the same 3× margin as Default's 1.5ms over 0.5ms). Its T3 burst credit is configured but inactive (§4).

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
  ├── IRQ context?        → stamp CAKE_FLOW_IRQ_WAKE on tctx
  ├── scx_bpf_select_cpu_dfl() finds an idle CPU (SCX_WAKE_SYNC placement is the kernel's)
  │     → hybrid: if the pick is an E-core, repeat the search from a P-core hint, keep it only if idle
  │     → direct dispatch via SCX_DSQ_LOCAL_ON
  └── All busy            → return prev_cpu

enqueue
  ├── now = scx_bpf_now(), LLC = cpu_llc_id[task_cpu(p)]
  ├── kthread without ctx → queue with a T1 deadline
  ├── not a wakeup (slice expiry, kick, yield, new task) → queue at own tier, base-quantum slice
  ├── stamp enqueue_time for dispatch latency measurement
  ├── slept >500ms?       → move avg_runtime halfway to the tier midpoint (post-sleep recovery)
  ├── IRQ_WAKE flag       → tier = T0 (one-shot, consumed here)
  ├── Waker mailbox       → promote wakee tier if waker is higher priority (floor T1)
  ├── New-flow / lock-holder flag → deadline advance, capped within the tier
  ├── vtime = now + tier budget - advance
  ├── insert into per-LLC DSQ
  └── T0/T1: kick the lowest-numbered T3 CPU in the LLC, else the lowest-numbered T2 CPU

dispatch
  ├── pull from local LLC DSQ
  └── if nothing runnable: steal from other LLCs (lowest ETD cost first, then index order)

running   → stamp last_run_at, update jitter_ewma_us from enqueue_time, consume enqueue_time,
            publish tier to per-CPU mailbox, set tier bitmask
tick      → past next_slice with a task queued in the LLC or local DSQ → self-kick;
            mailbox + DVFS update
stopping  → clear tier bitmask (before reclassify), then reclassify:
            add the bout to the burst; EWMA on the burst (no promotion while still runnable);
            DRR++ deficit charged per bout; recompute next_slice on every full pass;
            if tier changed: reset reclass_counter, zero burst_credit
```

### Key Data Structures

| Structure | Size | Purpose |
| :--- | :--- | :--- |
| `imperator_task_ctx` | 64B (1 cache line) | Per-task EWMA state, tier, deficit, burst accumulator, lock flags, dispatch latency EWMA, burst credit |
| `mega_mailbox_entry` | 64B (1 cache line) | Per-CPU tier broadcast for waker inheritance |
| `imperator_stats` | variable | Aggregated scheduler counters including burst credit earning and consumption rates |

### `imperator_task_ctx` Layout

| Bytes | Field | Purpose |
| :--- | :--- | :--- |
| 0–7 | `next_slice` | Time slice for next dispatch |
| 8–15 | `deficit_avg_fused` / `packed_info` | DRR++ deficit, avg_runtime, tier, flags |
| 16–19 | `last_run_at` | Timestamp of last dispatch start |
| 20–21 | `reclass_counter` | Graduated backoff counter |
| 22 | `overrun_count` | 8-bit shift register of per-sample overrun history |
| 23 | `lock_skip_count` | Consecutive starvation skips while holding a lock |
| 24 | `pending_futex_op` | Futex op recorded at syscall entry for cross-CPU exit matching |
| 25–27 | `__align_pad` | Explicit alignment gap before u32 field |
| 28–31 | `enqueue_time` | Wall-clock ns at queue entry; consumed after one use |
| 32–33 | `jitter_ewma_us` | Per-task dispatch latency EWMA in ~µs |
| 34–35 | `burst_credit` | Accumulated preemption-recovery credit in kns units |
| 36–39 | `sleep_entry_time` | Wall-clock ns at last blocking-sleep entry; consumed by post-sleep recovery in `enqueue` |
| 40–41 | `burst_acc_us` | CPU time (~µs, saturating at 65535) summed across preempted bouts since the task last slept |
| 42–63 | `__pad` | Reserved |

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

When a T0 or T1 task is queued while every CPU is busy, a victim CPU in the same LLC is kicked immediately: the lowest-numbered CPU running a T3 task, or failing that the lowest-numbered CPU running a T2 task. T0 and T1 CPUs are never kicked to run another latency-critical task, and T2/T3 enqueues never kick (A/B testing showed a 1% low regression). Every CPU in the LLC is a candidate; up to Gen 4 the candidate mask was built from the compile-time `nr_cpus = 8`, so CPUs 8 and above were never kicked.

---

## 8. Overhead

> [!NOTE]
> The figures below were measured against an earlier revision and have not been re-profiled since. Several features added later in this scheduler's history (ETD-aware steal ordering, the M-2 mailbox-consistency fix, the post-sleep recovery check moving from `stopping` to `enqueue`, and every Gen 5 change) touch the functions listed here; the notes column records what changed, but the numbers do not reflect it. Treat this table as directionally useful, not as a current measurement.

The added cost relative to a minimal sched_ext skeleton is approximately 20%, concentrated in `select_cpu` and `enqueue`. The cycle counts below predate the ETD-aware steal-ordering feature in `dispatch` (see [§7](#7-work-stealing--topology)) and have not been re-measured since; treat the `dispatch` row as **not current** rather than as a measured zero.

| Function | Added cost | Notes |
| :--- | :--- | :--- |
| `select_cpu` | ~2 cycles | Task storage fetched only on IRQ-context wakeups. Gen 5 removed the SYNC fast path and the scratch writes on the all-busy path |
| `enqueue` | +6 cycles steady-state | Mailbox read is the baseline cost. Gen 5 adds `scx_bpf_now()` and `scx_bpf_task_cpu()` calls; the burst-credit path is never reached (§4) |
| `dispatch` | *unmeasured since ETD-steal was added* | Local-LLC-empty path computes a cheapest-cost candidate across LLCs before falling back to index order. Gen 5 adds one `scx_bpf_dsq_nr_queued()` read when a pull fails |
| `tick` | +2 cycles | Gen 5: up to two `scx_bpf_dsq_nr_queued()` reads once the running task passes `next_slice`; removes up to HZ self-kicks per second on a CPU running a lone busy task |
| `running` | +11 cycles | Mailbox write + tier bitmask set + jitter EWMA update (idle-path dispatch: +2 cycles — guard branch only) |
| `stopping` | +5 cycles | Tier bitmask clear. Gen 5 adds the burst accumulator update |
| `lock_bpf` probes | ~50 ns | Not loaded by the current loader (§4) |

All per-task fields (`enqueue_time`, `jitter_ewma_us`, `burst_credit`, `burst_acc_us`) sit on the same 64B cache line as `last_run_at` and `next_slice`. No additional cache misses are introduced on any path.

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
| **Burst Credit** | Per-task slice extension credit meant to be earned by T1/T2 tasks on each preemption (T3 too, Sim profile only). Inactive: the kernel never passes `SCX_ENQ_PREEMPT` to `ops.enqueue` (§4). |
| **kns** | Kilonanoseconds — nanoseconds divided by 1024 (right-shift by 10). Internal unit used for deficit and burst credit to keep values in u16 range. |

### Architecture

| Term | Definition |
| :--- | :--- |
| **Fused Config** | 3 parameters packed into one 64-bit word: `[mult:12][quantum:16][starve:20]`, with 16 bits reserved. A `budget` field previously occupied bits 28–43 but was never read by any scheduling decision; it was removed and `starve` repacked down into the freed range rather than leaving a gap. `starve` holds the tier's deadline budget. |
| **Mega-Mailbox** | 64B per-CPU cache-line-isolated state. Carries tier information for waker inheritance with zero false sharing. |
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
| Lock-holder detection and starvation skip | scx_lavd (`lock.bpf.c`) |
| Burst-since-last-sleep classification | scx_lavd (`acc_runtime`; `max(avg_runtime, acc_runtime)` in `calc_sum_runtime_factor()`) |
| Per-tier deadline ordering | Original (Gen 5) — replaces strict tier priority with bounded waiting while keeping tier order for same-time arrivals |
| Dispatch latency telemetry (`jitter_ewma_us`) | Original — closes the per-task jitter measurement gap |
| Preemption burst credit (DRR++ extension) | Original — leaky-bucket burst allowance applied to CPU time-slice management |
| ETD-aware steal ordering (cheapest-LLC-first) | Original — extends ETD calibration from a fallback-avoidance signal into an active steal-ordering input |
| Desktop-first DVFS policy (no T3 throttle, deadline-bounded instead) | Original — replaces frequency throttling with deadline budgets as the mechanism bounding background-task impact |

---

## 10. Known Limitations

| Area | Current behavior |
| :--- | :--- |
| **Heavy main threads** | A thread that needs more than 8ms of CPU per frame (only possible below 125 fps, e.g. the main thread of a CPU-heavy title) classifies as T3 and sorts behind T2 work. Candidate fixes: raise `TIER_GATE_T2`, or require a low wakeup rate before T3. |
| **IRQ-wake scope** | Timer expirations are hardirq wakeups (§4), so every task waking from a timed sleep gets a one-dispatch T0 boost, background tasks included. |
| **Lock-holder protection** | Not loaded (§4). |
| **Preemption burst credit** | Never accrues (§4). |
| **Tick starvation path** | Phase 2 of `imperator_tick` (starvation kick, lock-holder skip) cannot fire: every budget exceeds its slice, so the slice check kicks first whenever anything is queued. Bounded waiting comes from deadline ordering instead. `starvation_preempts` and `lock_holder_skips` in `--stats` always read 0. |
| **Fork inheritance / exec reset** | Coded in `imperator_init_task` but never run (§3). |
| **Sole-occupant DVFS path** | Never runs: `rq->scx.nr_running` counts the running task, so it is never 0 in `ops.tick`. No effect while every tier targets `SCX_CPUPERF_ONE`. |
| **Kick victim choice** | Always the lowest-numbered candidate, so a burst of T0/T1 wakeups kicks the same CPU until it switches tasks. |
| **Slice expiry** | `ops.dispatch` takes the queue head without comparing it to the task whose slice just ended, so an expiring T2 task yields to a waiting T3 task. |
| **Hybrid steering** | The first idle search has already claimed an E-core's idle bit; when the P-core retry succeeds, that E-core stays marked busy until it next passes through idle. The P-core scan doesn't check idleness (§7). |
| **Nice changes** | Read once per task (§3). |
| **Waker inheritance on 6.12–6.14** | Wakelist-delivered wakeups read the target CPU's mailbox (§4). |
| **CPU count** | Per-CPU arrays hold 64 entries and CPU indices are masked with `& 63`; nothing refuses to load on larger systems. |
| **Build** | With clang 21, `bpf_compat.h`'s `__atomic_load_n` path needs `-mcpu=v4`; `-mcpu=v3` fails in instruction selection. |

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
