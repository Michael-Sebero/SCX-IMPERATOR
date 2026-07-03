// SPDX-License-Identifier: GPL-2.0
// scx_imperator - sched_ext scheduler applying CAKE bufferbloat concepts to CPU scheduling

mod calibrate;
mod stats;
mod topology;
mod tui;

use core::sync::atomic::Ordering;
use std::os::fd::AsRawFd;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use log::{info, warn};
use nix::sys::signal::{SigSet, Signal};
use nix::sys::signalfd::{SfdFlags, SignalFd};
#[allow(non_camel_case_types, non_upper_case_globals, dead_code)]
mod bpf_intf {
    include!(concat!(env!("OUT_DIR"), "/bpf_intf.rs"));
}
#[allow(non_camel_case_types, non_upper_case_globals, dead_code)]
mod bpf_skel {
    include!(concat!(env!("OUT_DIR"), "/bpf_skel.rs"));
}
use bpf_skel::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Profile {
    /// Minimum-latency competitive FPS profile. Tightest T0/T1/T2 thresholds
    /// of any profile; trades smooth long-tail frame pacing for the lowest
    /// possible worst-case input/render latency.
    Esports,
    /// Default desktop-gaming profile (`sudo scx_imperator` with no flags,
    /// or `--profile default` / `--profile gaming` explicitly — both names
    /// work and select this exact same profile; there is no separate
    /// "Gaming" config to confuse this with).
    ///
    /// Tuned for a single-PC, mains-powered desktop gaming workload: audio
    /// and input (T0) get the tightest possible slice and starvation ceiling
    /// since that work is inherently short-lived and the desktop has CPU
    /// headroom to spare for it; the render/game-logic thread (T2) is bounded
    /// to <3 frame-times of starvation at 144Hz so background work (shader
    /// compilation, asset streaming, Discord, OBS, etc.) cannot visibly
    /// stutter the frame. Combined with full-clock DVFS on every tier (see
    /// tier_perf_target[] in imperator_bpf.c) and lock-holder priority
    /// boosting (lock_bpf.c) for Wine/Proton D3D submission threads, this
    /// profile requires no additional configuration on a desktop PC.
    #[value(alias = "gaming")]
    Default,
    /// Simulation / strategy game profile.
    ///
    /// Optimises for workloads with a dominant long-running simulation or
    /// open-world streaming thread (RTS, 4X, city-builder, open-world RPG)
    /// rather than many short-burst latency-critical threads.
    ///
    /// Changes vs the Default profile:
    ///   - Larger quantum (4ms) reduces context-switch overhead on sustained T2/T3
    ///   - Looser starvation thresholds: T3 gets 200ms before forced preemption
    ///     (matches Legacy) since nothing latency-critical is competing for the core
    ///   - T3 burst credit enabled (see tier_burst_cap_kns in imperator_bpf.c):
    ///     a simulation thread repeatedly preempted by background system work
    ///     earns slice extensions proportional to how often it was interrupted
    ///   - T0/T1 thresholds are unchanged — audio and input remain protected
    ///
    /// FPS workloads running under this profile will behave correctly but
    /// may experience slightly higher background-task latency (looser T3
    /// starvation) than Default. Use Default/Esports for competitive FPS.
    Sim,
}

impl Profile {
    fn values(&self) -> (u64, u64, u64) {
        match self {
            Profile::Esports => (1000, 4000, 50000),
            Profile::Default => (2000, 8000, 100000),
            // Sim: 4ms quantum (matches Legacy — reduces context-switch overhead
            // on sustained T2/T3 work), 8ms new-flow bonus (matches Default),
            // 200ms T3 starvation (matches Legacy — sim threads are long-running
            // by nature and nothing latency-critical competes with them).
            Profile::Sim => (4000, 8000, 200000),
        }
    }

    fn starvation_threshold(&self) -> [u64; 8] {
        match self {
            Profile::Esports => [
                1_500_000, 4_000_000, 20_000_000, 50_000_000,
                50_000_000, 50_000_000, 50_000_000, 50_000_000,
            ],
            // DESKTOP POLICY (default): scx_imperator targets desktop PCs only —
            // mains-powered, no thermal/battery constraint — so the Default
            // profile is tuned as a real desktop-gaming profile rather than a
            // generic middle ground between Esports and Legacy.
            //
            // T0 tightened 3ms -> 1.5ms (matches Esports): there is no reason to
            // tolerate slower worst-case input/audio latency on a desktop with
            // CPU headroom to spare — this is a free win with no throughput cost
            // since T0 work is inherently short-lived.
            //
            // T2 tightened 40ms -> 20ms (matches Esports): 40ms is ~5.7 frames at
            // 144Hz and ~3.3 frames at 240Hz — long enough for a starved render
            // thread to produce a visible stutter on a high-refresh desktop
            // monitor, which is the realistic target display for this profile.
            // 20ms bounds worst-case render-thread starvation to <3 frames at
            // 144Hz while remaining looser than Esports' T0/T1 (this profile
            // still favors smoother frame pacing over Esports' minimum-latency
            // input path).
            //
            // T1/T3 and quantum/new-flow-bonus are unchanged from the validated
            // baseline (see CAKE_DEFAULT_STARVATION_T3 in intf.h and the Arc
            // Raiders A/B note on enqueue-time kicks) — only T0/T2 needed
            // tightening to reflect desktop-gaming intent.
            Profile::Default => [
                1_500_000, 8_000_000, 20_000_000, 100_000_000,
                100_000_000, 100_000_000, 100_000_000, 100_000_000,
            ],
            // Sim: T0 loosened relative to Default (3ms vs Default's 1.5ms) —
            // these no longer match, despite the original gen7.5 comment claiming
            // "T0/T1 identical to Gaming" (the profile this comment refers to was
            // later renamed Default — see Profile enum). That claim predated the
            // desktop retune above; Default tightened T0 and Sim did not follow.
            // Left as-is deliberately rather than tightened to match: with the T0
            // multiplier fix below (256, giving a 1ms T0 slice at Sim's 4ms
            // quantum), 3ms starvation keeps the same 3x starvation:slice safety
            // margin as Default (1.5ms / 0.5ms slice = 3x) and Esports (6x) — i.e.
            // Sim's T0 is proportionally just as protected, scaled to its longer
            // base quantum, not literally identical in absolute terms. T1 still
            // matches Default exactly (8ms both). T2 loosened to 80ms (matches
            // Legacy — render threads in sim games have longer, more variable
            // frame times than in FPS titles), T3 at 200ms (matches Legacy — sim
            // thread is long-running by design, nothing latency-critical is
            // competing).
            Profile::Sim => [
                3_000_000, 8_000_000, 80_000_000, 200_000_000,
                200_000_000, 200_000_000, 200_000_000, 200_000_000,
            ],
        }
    }

    fn tier_multiplier(&self) -> [u32; 8] {
        match self {
            Profile::Esports => [256, 1024, 2048, 4095, 4095, 4095, 4095, 4095],
            // DESKTOP POLICY: T0 multiplier matches Esports (256, not 512).
            // At the 2ms Default-profile quantum, multiplier 512 gave T0 a ~1ms
            // slice — generous for "Critical" work (IRQ handlers, audio
            // callbacks, input) that is inherently short-lived and runs many
            // times per frame. 256 halves it to ~0.5ms, the same T0 slice as
            // Esports. This is a free responsiveness win: T0 tasks naturally
            // finish well under either slice, so the shorter cap only bites —
            // and only helps — on the rare pathological T0 task that overruns,
            // capping its worst-case hold time on the core sooner.
            Profile::Default => [256, 1024, 2048, 4095, 4095, 4095, 4095, 4095],
            // FIX (gen7.5-arithmetic): comment previously claimed Sim's 4ms quantum
            // at multiplier=512 gave a "~1ms slice, matching what Gaming used to
            // provide" (the profile referred to here was later renamed Default —
            // see Profile enum). That arithmetic was wrong: slice = quantum *
            // (mult/1024), so 4ms * (512/1024) = 2.0ms, not 1ms — double the old
            // Default profile's actual T0 slice (1ms) and quadruple the current
            // Default's (0.5ms). Sim's worst-case T0 hold time was never actually
            // equivalent to Default's; it silently grew further out of step the
            // moment Default tightened above.
            //
            // Tightened 512 -> 256 to restore the same ~1ms T0 slice this comment
            // always intended Sim to have (4ms * (256/1024) = 1ms — verified below).
            // Same free-win rationale as Default's T0 tightening above: T0 work
            // (audio/input) is short-lived regardless of profile, so capping its
            // worst-case hold time tighter only helps the rare pathological case
            // and costs nothing on the common path. This still leaves Sim's T0
            // slice 2x Default's (1ms vs 0.5ms) since Sim's base quantum is 2x
            // Default's (4ms vs 2ms) — that gap is real and intentional, not a
            // typo; Sim is the one profile where the base quantum itself is
            // deliberately longer (see Profile::values(), "reduces context-switch
            // overhead on sustained T2/T3 work"), so its T0 slice scales with it
            // by design. T1/T2 unchanged, T3 multiplier at 4095 (same as
            // Default/Esports max) — with a 4ms base quantum, T3 gets up to ~16ms
            // quanta, reducing context-switch fragmentation for sustained
            // simulation work.
            Profile::Sim => [256, 1024, 2048, 4095, 4095, 4095, 4095, 4095],
        }
    }

    // FIX (audit/F-03): wait_budget() removed. It computed distinct,
    // deliberately profile-tuned per-tier "wait budget" values (Esports:
    // 50µs/1ms/4ms; Default: 100µs/2ms/8ms; Sim: 100µs/2ms/16ms; T3 always
    // 0) that were packed into tier_configs and transmitted to BPF RODATA —
    // but UNPACK_BUDGET_NS was never called by any BPF code path, confirmed
    // by exhaustive grep across imperator_bpf.c and lock_bpf.c. No design
    // rationale for what the field was meant to drive existed anywhere in
    // the codebase (unlike sleep_entry_time or dsq_hint, both of which had
    // full mechanism writeups this audit could restore). Rather than guess
    // at unspecified scheduling behavior and add a new, unvalidated hot-path
    // mechanism to a codebase whose own history (see intf.h's tier_perf_target
    // / T2 DVFS note) already shows what happens when a tuning value ships
    // without this project's normal A/B validation, the field and its BPF-side
    // plumbing (CFG_SHIFT_BUDGET / CFG_MASK_BUDGET / UNPACK_BUDGET_NS /
    // CAKE_DEFAULT_WAIT_BUDGET_* in intf.h) have been removed. Starvation has
    // been repacked down to bit 28 to reclaim the freed range rather than
    // leave a hole in tier_configs — see intf.h's fused_config_t comment.

    fn tier_configs(&self, quantum_us: u64, starvation_override: Option<u64>) -> [u64; 8] {
        let base_starvation = self.starvation_threshold();
        let multiplier = self.tier_multiplier();

        let starvation: [u64; 8] = if let Some(cli_us) = starvation_override {
            let cli_ns = cli_us * 1000;
            let default_t3 = base_starvation[3];
            if default_t3 > 0 {
                base_starvation.map(|s| s * cli_ns / default_t3)
            } else {
                base_starvation
            }
        } else {
            base_starvation
        };

        let mut configs = [0u64; 8];
        for i in 0..8 {
            let quantum_kns = (quantum_us * 1000) >> 10;
            configs[i] = (multiplier[i] as u64 & 0xFFF)
                | ((quantum_kns & 0xFFFF) << 12)
                | (((starvation[i] >> 10) & 0xFFFFF) << 28);
        }
        configs
    }
}

/// 🍰 scx_imperator: A sched_ext scheduler applying CAKE bufferbloat concepts
///
/// DESKTOP PCs ONLY. `sudo scx_imperator` with no flags runs the desktop
/// Default profile (a.k.a. `--profile gaming`, an accepted alias for the
/// same profile) — no laptop battery, thermal, or server power-saving logic
/// exists in this scheduler to configure or disable.
///
/// 4-TIER SYSTEM (classified by avg_runtime):
///   T0 Critical  (<100µs): IRQ, input, audio, network
///   T1 Interact  (<2ms):   compositor, physics, AI
///   T2 Frame     (<8ms):   game render, encoding
///   T3 Bulk      (≥8ms):   compilation, background
#[derive(Parser, Debug)]
#[command(author, version, about = "🍰 scx_imperator scheduler", verbatim_doc_comment)]
struct Args {
    /// Scheduling profile. Default requires no other flags and is tuned for
    /// a single mains-powered desktop gaming PC. `--profile gaming` is an
    /// accepted alias for the same profile.
    #[arg(long, short, value_enum, default_value_t = Profile::Default)]
    profile: Profile,
    #[arg(long)]
    quantum: Option<u64>,
    #[arg(long)]
    new_flow_bonus: Option<u64>,
    #[arg(long)]
    starvation: Option<u64>,
    #[arg(long, short)]
    verbose: bool,
    #[arg(long, default_value_t = 1)]
    interval: u64,
}

impl Args {
    fn effective_values(&self) -> (u64, u64, u64) {
        let (q, nfb, starv) = self.profile.values();
        (
            self.quantum.unwrap_or(q),
            self.new_flow_bonus.unwrap_or(nfb),
            self.starvation.unwrap_or(starv),
        )
    }
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    args: Args,
    topology: topology::TopologyInfo,
    latency_matrix: Arc<Mutex<Vec<Vec<f64>>>>,
    /// eventfd read end: fires once when ETD calibration completes.
    /// -1 if creation failed (non-fatal: falls back to 60 s timeout polling).
    etd_efd: i32,
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        if self.etd_efd >= 0 {
            unsafe { libc::close(self.etd_efd) };
        }
    }
}

impl<'a> Scheduler<'a> {
    fn new(
        args: Args,
        open_object: &'a mut std::mem::MaybeUninit<libbpf_rs::OpenObject>,
    ) -> Result<Self> {
        use libbpf_rs::skel::{OpenSkel, SkelBuilder};

        let skel_builder = BpfSkelBuilder::default();
        let mut open_skel = skel_builder
            .open(open_object)
            .context("Failed to open BPF skeleton")?;

        scx_utils::import_enums!(open_skel);

        let topo = topology::detect()?;
        let (quantum, new_flow_bonus, _) = args.effective_values();

        // ── eventfd for ETD completion notification ───────────────────────
        // The background thread writes to this fd when calibration finishes.
        // The event loop polls [signalfd, etd_efd] and shrinks to [signalfd]
        // after the eventfd fires — matching s6's dynamic poll-set pattern.
        //
        // EFD_NONBLOCK: read() returns EAGAIN instead of blocking when empty.
        // EFD_CLOEXEC:  not inherited across exec.
        let etd_efd = unsafe {
            libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC)
        };
        if etd_efd < 0 {
            warn!(
                "Failed to create ETD eventfd ({}), falling back to 60s timeout polling",
                std::io::Error::last_os_error()
            );
        }

        // Duplicate the fd for the background thread (write end).
        // Scheduler owns etd_efd (read, closed in Drop).
        // Thread owns etd_efd_write (write, closed by thread after signalling).
        let etd_efd_write = if etd_efd >= 0 {
            let fd = unsafe { libc::dup(etd_efd) };
            if fd < 0 {
                warn!("dup(etd_efd) failed — falling back to timeout polling");
                -1i32
            } else {
                fd
            }
        } else {
            -1i32
        };

        info!("Starting ETD calibration in background...");
        let nr_cpus_cal = topo.nr_cpus;
        let latency_matrix = Arc::new(Mutex::new(vec![vec![0.0f64; nr_cpus_cal]; nr_cpus_cal]));
        let matrix_bg = latency_matrix.clone();
        let is_verbose = args.verbose;

        std::thread::spawn(move || {
            let result = calibrate::calibrate_full_matrix(
                nr_cpus_cal,
                &calibrate::EtdConfig::default(),
                |current, total, is_complete| {
                    if !is_verbose {
                        tui::render_calibration_progress(current, total, is_complete);
                    }
                },
            );
            match matrix_bg.lock() {
                Ok(mut m)  => *m = result,
                Err(e)     => *e.into_inner() = result,
            }
            // Signal ETD completion.  The event loop wakes within microseconds
            // and writes the LLC cost table — not up to 1 second later.
            if etd_efd_write >= 0 {
                let val: u64 = 1;
                unsafe {
                    libc::write(
                        etd_efd_write,
                        &val as *const u64 as *const libc::c_void,
                        8,
                    );
                    libc::close(etd_efd_write);
                }
            }
        });

        // Configure BPF rodata
        if let Some(rodata) = &mut open_skel.maps.rodata_data {
            rodata.quantum_ns       = quantum * 1000;
            rodata.new_flow_bonus_ns = new_flow_bonus * 1000;
            rodata.enable_stats     = args.verbose;
            rodata.tier_configs     = args.profile.tier_configs(quantum, args.starvation);
            rodata.has_hybrid       = topo.has_hybrid_cores;

            // Gap-4 / Suggestion 1: Wire big_cpu_mask to BPF RODATA.
            // topology.rs computes this as a u64 bitmask of P-core / big-core
            // CPU IDs during sched_ext attachment.  Previously this field was
            // computed but never written to BPF — imperator knew hybrid cores
            // existed (has_hybrid) but had no placement information about which
            // specific CPUs were P-cores.  Writing it here completes the wiring
            // that enables imperator_select_cpu's idle-path P-core preference.
            // On non-hybrid systems: big_cpu_mask stays 0 (default), and the
            // has_hybrid=false RODATA gate in BPF ensures the mask is never read.
            rodata.big_cpu_mask     = topo.big_cpu_mask;

            // Wire the five previously-dead topology fields to BPF RODATA.
            // These were computed correctly in topology.rs and received correctness
            // fixes this session but were never forwarded to BPF until now.
            //
            // cpu_core_id: physical core ID per logical CPU — bridge from CPU
            //   index to core_cpu_mask / core_thread_mask lookups in BPF.
            // cpu_thread_bit: SMT thread slot bitmask per logical CPU — used in
            //   core occupancy checks for fully-idle core detection.
            // core_cpu_mask: 64-bit bitmask of all logical CPUs per physical
            //   core — enables SMT-aware hybrid placement steering.
            // core_thread_mask: bitmask of all SMT slots per physical core —
            //   denominator for fully-idle core detection.
            // threads_per_ccd: logical CPU count of largest CCD — CCD-fill
            //   threshold for work-stealing: don't steal from an LLC with fewer
            //   queued tasks than it has CPU threads.
            for (i, &v) in topo.cpu_core_id.iter().enumerate().take(64) {
                rodata.cpu_core_id[i] = v as u32;
            }
            for (i, &v) in topo.cpu_thread_bit.iter().enumerate().take(64) {
                rodata.cpu_thread_bit[i] = v as u32;
            }
            for (i, &v) in topo.core_cpu_mask.iter().enumerate().take(32) {
                rodata.core_cpu_mask[i] = v;
            }
            for (i, &v) in topo.core_thread_mask.iter().enumerate().take(32) {
                rodata.core_thread_mask[i] = v as u32;
            }
            rodata.threads_per_ccd  = topo.threads_per_ccd;

            // Suggestion 3: sim_mode enables T3 burst credit in imperator_enqueue.
            // In Default/Esports profiles, T3 burst credit is always 0 (T3 bulk
            // work should not earn slice extensions when preempted by T0/T1).
            // In Sim profile, T3 may be the dominant workload with nothing
            // latency-critical competing — T3 burst credit lets a simulation
            // thread earn recovery time when repeatedly preempted by background
            // system work (kworkers, kswapd, etc.) rather than T0/T1 peers.
            rodata.sim_mode         = matches!(args.profile, Profile::Sim);

            let llc_count = topo.llc_cpu_mask.iter().filter(|&&m| m != 0).count() as u32;
            rodata.nr_llcs = llc_count.max(1);
            rodata.nr_cpus = topo.nr_cpus.min(64) as u32;
            for (i, &llc_id) in topo.cpu_llc_id.iter().enumerate() {
                rodata.cpu_llc_id[i] = llc_id as u32;
            }
            // NOTE: llc_cpu_mask is NOT written from Rust.
            // imperator_init (BPF side) computes it from cpu_llc_id at scheduler
            // attachment time — before any task is scheduled.  This eliminates
            // the partial-deploy hazard where a missing write left the mask
            // all-zeros, causing silent kick failures.
        }

        let skel = open_skel.load().context("Failed to load BPF program")?;

        Ok(Self { skel, args, topology: topo, latency_matrix, etd_efd })
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<()> {
        let _link = self
            .skel
            .maps
            .imperator_ops
            .attach_struct_ops()
            .context("Failed to attach scheduler")?;

        self.show_startup_splash()?;

        let mut etd_written = self.try_write_etd_costs();

        if self.args.verbose {
            tui::run_tui(
                &mut self.skel,
                shutdown.clone(),
                self.args.interval,
                self.topology.clone(),
            )?;
        } else {
            let mut mask = SigSet::empty();
            mask.add(Signal::SIGINT);
            mask.add(Signal::SIGTERM);
            mask.thread_block().context("Failed to block signals")?;

            let sfd = SignalFd::with_flags(&mask, SfdFlags::SFD_NONBLOCK)
                .context("Failed to create signalfd")?;

            use nix::poll::{poll, PollFd, PollFlags};
            use std::os::fd::BorrowedFd;

            // Build a fixed-size poll array.  fds[0] = signalfd (always polled).
            // fds[1] = etd_efd when available, else signalfd again as a dummy
            // (safe: n_fds == 1 when etd_efd < 0, so fds[1] is never passed to poll).
            //
            // Constructing both entries from raw fds avoids moving signal_pfd
            // into the else-arm before using it in the array (PollFd is not Copy).
            let active_etd_fd = if self.etd_efd >= 0 { self.etd_efd } else { sfd.as_raw_fd() };
            let mut fds = unsafe {
                [
                    PollFd::new(BorrowedFd::borrow_raw(sfd.as_raw_fd()), PollFlags::POLLIN),
                    PollFd::new(BorrowedFd::borrow_raw(active_etd_fd),   PollFlags::POLLIN),
                ]
            };

            loop {
                // Dynamic fd count: mirrors s6's `iopause_g(x, 2 + (notifyfd >= 0))`.
                // After ETD fires (etd_written=true) or if the fd is unavailable,
                // shrink to 1 — steady state polls only the signalfd.
                let n_fds: usize = if etd_written || self.etd_efd < 0 { 1 } else { 2 };

                let result = poll(&mut fds[..n_fds], nix::poll::PollTimeout::from(60_000u16));

                match result {
                    Ok(n) if n > 0 => {
                        // Check etd eventfd first (non-blocking — EAGAIN if signalfd-only event).
                        if !etd_written && self.etd_efd >= 0 {
                            let mut val = 0u64;
                            let r = unsafe {
                                libc::read(
                                    self.etd_efd,
                                    &mut val as *mut u64 as *mut libc::c_void,
                                    8,
                                )
                            };
                            if r == 8 {
                                etd_written = self.try_write_etd_costs();
                                if !etd_written {
                                    warn!("ETD eventfd fired but matrix still empty — will retry at next timeout");
                                }
                            }
                        }

                        // Check signalfd.
                        match sfd.read_signal() {
                            Ok(Some(siginfo)) => {
                                // Exhaustive match — unexpected signals are programming errors.
                                match siginfo.ssi_signo as i32 {
                                    libc::SIGINT | libc::SIGTERM => {
                                        info!("Received signal {} — shutting down", siginfo.ssi_signo);
                                        shutdown.store(true, Ordering::Relaxed);
                                    }
                                    other => {
                                        warn!("Unexpected signal {} on signalfd — this is a bug", other);
                                    }
                                }
                                break;
                            }
                            Ok(None) | Err(nix::errno::Errno::EAGAIN) => {
                                // signalfd not ready — only ETD fd fired; continue.
                            }
                            Err(e) => {
                                warn!("read_signal error: {}", e);
                                break;
                            }
                        }
                    }
                    Ok(_) => {
                        // 60 s timeout: retry ETD write (covers eventfd-unavailable path)
                        // and check for BPF scheduler exit via UEI.
                        if !etd_written {
                            etd_written = self.try_write_etd_costs();
                        }
                        if scx_utils::uei_exited!(&self.skel, uei) {
                            match scx_utils::uei_report!(&self.skel, uei) {
                                Ok(reason) => warn!("BPF scheduler exited: {:?}", reason),
                                Err(e)     => warn!("BPF scheduler exited (reason unavailable: {})", e),
                            }
                            break;
                        }
                    }
                    Err(nix::errno::Errno::EINTR) => {
                        if shutdown.load(Ordering::Relaxed) { break; }
                    }
                    Err(e) => {
                        warn!("poll() error: {}", e);
                        break;
                    }
                }
            }
        }

        info!("scx_imperator scheduler shutting down");
        Ok(())
    }

    /// Compress the ETD matrix into per-LLC-pair costs and write to BPF BSS.
    ///
    /// Returns true when data was written, false when calibration is still
    /// in progress (matrix all-zeros) or the mutex is contested.
    ///
    /// Uses try_lock() so a contested mutex causes a fast retry at the next
    /// wakeup rather than blocking the event loop.  With the eventfd mechanism,
    /// the thread releases the mutex before firing the fd, so contention in
    /// practice is impossible — try_lock() is defense-in-depth.
    fn try_write_etd_costs(&mut self) -> bool {
        let matrix = match self.latency_matrix.try_lock() {
            Ok(m)  => m.clone(),
            Err(_) => return false,
        };

        if !matrix.iter().flatten().any(|&v| v > 0.0) {
            return false;
        }

        let nr_cpus = matrix.len().min(topology::MAX_CPUS);
        let nr_llcs = self
            .topology
            .llc_cpu_mask
            .iter()
            .filter(|&&m| m != 0)
            .count()
            .min(topology::MAX_LLCS);

        let matrix_ref = &matrix;

        if let Some(bss) = &mut self.skel.maps.bss_data {
            for llc_a in 0..nr_llcs {
                for llc_b in 0..nr_llcs {
                    if llc_a == llc_b { continue; }
                    let min_ns = (0..nr_cpus)
                        .filter(|&ca| self.topology.cpu_llc_id[ca] as usize == llc_a)
                        .flat_map(|ca| {
                            (0..nr_cpus)
                                .filter(|&cb| self.topology.cpu_llc_id[cb] as usize == llc_b)
                                .filter_map(move |cb| {
                                    let v = matrix_ref[ca][cb];
                                    if v > 0.0 { Some(v) } else { None }
                                })
                        })
                        .fold(f64::MAX, f64::min);

                    let cost: u8 = if min_ns == f64::MAX {
                        0
                    } else {
                        // FIX (Bug-3): floor at 1 so a legitimately measured but
                        // sub-4ns result (physically impossible for cross-LLC but
                        // not rejected by the type system) is never written as 0.
                        // The BPF side uses `cost == 0` as "uncalibrated" sentinel;
                        // a 0 written here would cause that LLC pair to be skipped
                        // in ETD steal ordering, falling back to index order as if
                        // calibration had never run.  .max(1) is consistent with
                        // calibrate.rs's own 500ns sentinel for affinity failures.
                        ((min_ns / 4.0) as u64).min(255).max(1) as u8
                    };
                    bss.llc_etd_cost[llc_a][llc_b] = cost;
                }
            }
            info!("ETD: LLC cost table written ({} LLCs)", nr_llcs);
        }
        true
    }

    fn show_startup_splash(&self) -> Result<()> {
        let (q, _nfb, starv) = self.args.effective_values();
        let profile_str = format!("{:?}", self.args.profile).to_uppercase();
        let matrix = self
            .latency_matrix
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        tui::render_startup_screen(tui::StartupParams {
            topology: &self.topology,
            latency_matrix: &matrix,
            profile: &profile_str,
            quantum: q,
            starvation: starv,
        })
    }
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();
    let shutdown = Arc::new(AtomicBool::new(false));
    let mut open_object = std::mem::MaybeUninit::uninit();
    let mut scheduler = Scheduler::new(args, &mut open_object)?;
    scheduler.run(shutdown)?;
    Ok(())
}
