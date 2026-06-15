#!/bin/bash
# =============================================================================
# scx_imperator Interactive Benchmark Suite
# =============================================================================
#
# A unified tool to benchmark scx_imperator performance against baseline EEVDF.
# All functionality is self-contained.
#
# Usage: sudo ./scripts/benchmark.sh
#
# =============================================================================

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
LOG_DIR="$SCRIPT_DIR/logs"
START_SCRIPT="$ROOT_DIR/start.sh"
PROJECT_DIR="$ROOT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root (sudo)${NC}"
    exit 1
fi

# Ensure log directory exists
mkdir -p "$LOG_DIR"

# =============================================================================
# Data Collection Functions
# =============================================================================

get_bpf_stats() {
    bpftool prog show 2>/dev/null | awk '
    /struct_ops.*name imperator_/ {
        for (i=1; i<=NF; i++) {
            if ($i == "name" && $(i+1) ~ /^imperator_/) {
                gsub(/^imperator_/, "", $(i+1))
                name = $(i+1)
            }
        }
    }
    /xlated.*jited/ {
        for (i=1; i<=NF; i++) {
            if ($i == "xlated") { xlated = $(i+1); gsub(/B$/, "", xlated) }
            if ($i == "jited") { jited = $(i+1); gsub(/B$/, "", jited) }
        }
    }
    /run_time_ns.*run_cnt/ {
        for (i=1; i<=NF; i++) {
            if ($i == "run_time_ns") run_time = $(i+1)
            if ($i == "run_cnt") run_cnt = $(i+1)
        }
        if (name != "") {
            print name, xlated, jited, run_cnt, run_time
            name = ""
        }
    }
    '
}

# Read imperator_stats BPF map: nr_new_flow_dispatches, nr_old_flow_dispatches,
# nr_tier_dispatches[4], nr_starvation_preempts_tier[4],
# nr_lock_holder_skips, nr_irq_wake_boosts, nr_waker_tier_boosts.
#
# Struct layout (intf.h, all u64, little-endian):
#   [0]     nr_new_flow_dispatches
#   [8]     nr_old_flow_dispatches
#   [16-40] nr_tier_dispatches[0..3]   (Critical, Interactive, Frame, Bulk)
#   [48-72] nr_starvation_preempts_tier[0..3]
#   [80]    nr_lock_holder_skips
#   [88]    nr_irq_wake_boosts
#   [96]    nr_waker_tier_boosts
#
# Outputs 13 space-separated u64 values, or all zeros on failure.
get_imperator_stats() {
    python3 -c '
import subprocess, json, struct, sys

ZERO = "0 " * 13

try:
    r = subprocess.run(
        ["bpftool", "--json", "map", "dump", "name", "imperator_stats"],
        capture_output=True, text=True, timeout=3
    )
    if r.returncode != 0 or not r.stdout.strip():
        print(ZERO); sys.exit(0)

    data = json.loads(r.stdout)
    if not data:
        print(ZERO); sys.exit(0)

    # bpftool --json emits the value bytes as a list of ints for array maps
    raw_bytes = data[0].get("value", {}).get("", [])
    if not isinstance(raw_bytes, list) or len(raw_bytes) < 104:
        print(ZERO); sys.exit(0)

    bs = bytes(int(b) if isinstance(b, int) else int(b, 16) for b in raw_bytes)
    # 13 u64s: new_flow, old_flow, tier[4], starv[4], lock_skip, irq_boost, waker_boost
    vals = struct.unpack_from("<13Q", bs, 0)
    print(" ".join(str(v) for v in vals))
except Exception:
    print(ZERO)
'
}

get_interrupt_stats() {
    python3 -c '
import sys
res, loc, tlb = 0, 0, 0
for line in open("/proc/interrupts"):
    parts = line.split()
    if not parts: continue
    label = parts[0]
    if label in ["RES:", "LOC:", "TLB:"]:
        count = sum(int(x) for x in parts[1:] if x.isdigit())
        if label == "RES:": res = count
        elif label == "LOC:": loc = count
        elif label == "TLB:": tlb = count
print(f"{res} {loc} {tlb}")
'
}

get_cs_stats() {
    awk '/^ctxt/ {cs=$2} /^intr/ {intr=$2} END {print cs, intr}' /proc/stat
}

get_load() {
    awk '{print $1, $2, $3, $4}' /proc/loadavg
}

get_cpu_freq() {
    if [ -f /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq ]; then
        cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq 2>/dev/null | \
            awk '{sum+=$1; n++} END {if(n>0) print int(sum/n/1000); else print 0}'
    else
        echo 0
    fi
}

get_binary_size() {
    local binary="$PROJECT_DIR/target/release/scx_imperator"
    if [ -f "$binary" ]; then
        stat -c%s "$binary"
    else
        echo 0
    fi
}

get_perf_stats() {
    if command -v perf &>/dev/null; then
        perf stat -x, -e instructions,cycles,branches,branch-misses,dTLB-loads,dTLB-load-misses,cache-references,cache-misses,L1-dcache-loads,L1-dcache-load-misses \
            -a --timeout 1000 2>&1 | awk -F, '
            $3 == "instructions"        { instr = $1 }
            $3 == "cycles"              { cycles = $1 }
            $3 == "branches"            { branches = $1 }
            $3 == "branch-misses"       { branch_misses = $1 }
            $3 == "dTLB-loads"          { tlb_loads = $1 }
            $3 == "dTLB-load-misses"    { tlb_misses = $1 }
            $3 == "cache-references"    { refs = $1 }
            $3 == "cache-misses"        { misses = $1 }
            $3 == "L1-dcache-loads"     { l1_loads = $1 }
            $3 == "L1-dcache-load-misses" { l1_misses = $1 }
            END {
                instr += 0; cycles += 0; branches += 0; branch_misses += 0;
                tlb_loads += 0; tlb_misses += 0; refs += 0; misses += 0;
                l1_loads += 0; l1_misses += 0;

                ipc = 0; if (cycles > 0) ipc = instr / cycles;
                branch_miss_rate = 0; if (branches > 0) branch_miss_rate = (branch_misses / branches) * 100;
                tlb_miss_rate = 0; if (tlb_loads > 0) tlb_miss_rate = (tlb_misses / tlb_loads) * 100;
                llc_miss_rate = 0; if (refs > 0) llc_miss_rate = (misses / refs) * 100;
                l1d_miss_rate = 0; if (l1_loads > 0) l1d_miss_rate = (l1_misses / l1_loads) * 100;

                printf "%.2f %.2f %.2f %.2f %.2f\n", ipc, branch_miss_rate, tlb_miss_rate, llc_miss_rate, l1d_miss_rate
            }
        '
    else
        echo "0 0 0 0 0"
    fi
}

# =============================================================================
# Formatting Functions
# =============================================================================

print_menu_header() {
    clear
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║${NC}           ${BOLD}scx_imperator Interactive Benchmark Suite${NC}                 ${BOLD}${CYAN}║${NC}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_monitor_header() {
    local interval=$1
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║${NC}           ${BOLD}scx_imperator Performance Monitor${NC}                               ${BOLD}${CYAN}║${NC}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo -e "${DIM}Interval: ${interval}s | $(date '+%Y-%m-%d %H:%M:%S') | Press Ctrl+C to stop${NC}"
    echo
}

# =============================================================================
# Internal Execution Engines
# =============================================================================

run_baseline_internal() {
    local duration=$1
    local name=$2
    local log_file=$3

    echo 1 > /proc/sys/kernel/bpf_stats_enabled 2>/dev/null || true

    printf '{"type": "header", "scheduler": "EEVDF", "mode": "%s", "duration": %d, "timestamp": "%s", "kernel": "%s", "host": "%s"}\n' \
        "$name" "$duration" "$(date -Iseconds)" "$(uname -r)" "$(hostname)" > "$log_file"

    local interval=2
    local end_time=$(($(date +%s) + duration))
    local sample=0

    read prev_cs prev_intr <<< $(awk '/^ctxt/ {cs=$2} /^intr/ {intr=$2} END {print cs, intr}' /proc/stat)
    read prev_res prev_loc prev_tlb <<< $(get_interrupt_stats)

    declare -a ipc_samples branch_samples tlb_samples llc_samples l1d_samples

    (
        while [ $(date +%s) -lt $end_time ]; do
            read ipc branch tlb llc l1d <<< $(get_perf_stats)
            echo "$ipc $branch $tlb $llc $l1d" >> "${log_file}.perf_samples"
            sleep 1
        done
    ) &
    local perf_pid=$!

    while [ $(date +%s) -lt $end_time ]; do
        sample=$((sample + 1))
        local remaining=$((end_time - $(date +%s)))
        [ $remaining -lt 0 ] && remaining=0

        sleep $interval

        local ts=$(date +%s)
        read cs intr <<< $(awk '/^ctxt/ {cs=$2} /^intr/ {intr=$2} END {print cs, intr}' /proc/stat)
        read res loc tlb <<< $(get_interrupt_stats)

        local cs_per_sec=$(( (cs - prev_cs) / interval ))
        local intr_per_sec=$(( (intr - prev_intr) / interval ))

        local res_per_sec=$(( (res - prev_res) / interval ))
        local loc_per_sec=$(( (loc - prev_loc) / interval ))
        local tlb_per_sec=$(( (tlb - prev_tlb) / interval ))

        prev_cs=$cs
        prev_intr=$intr
        prev_res=$res
        prev_loc=$loc
        prev_tlb=$tlb

        local freq=$(get_cpu_freq)
        read load1 load5 load15 runnable <<< $(get_load)

        echo -ne "\r${CYAN}[Sample $sample] ${remaining}s left - CS: ${cs_per_sec}/s  Intr: ${intr_per_sec}/s (RES: ${res_per_sec})  Freq: ${freq}MHz${NC}   "

        printf '{"type": "sample", "seq": %d, "timestamp": %d, "metrics": {"context_switches_sec": %d, "interrupts_sec": %d, "interrupts_breakdown": {"res": %d, "loc": %d, "tlb": %d}, "cpu_freq_mhz": %d, "load_avg": [%s, %s, %s], "runnable_tasks": "%s"}}\n' \
            "$sample" "$ts" "$cs_per_sec" "$intr_per_sec" "$res_per_sec" "$loc_per_sec" "$tlb_per_sec" "$freq" "$load1" "$load5" "$load15" "$runnable" >> "$log_file"
    done

    wait $perf_pid 2>/dev/null || true

    echo ""
    echo -e "${CYAN}Calculating statistics from ${duration} perf samples...${NC}"

    if [ -f "${log_file}.perf_samples" ]; then
        read ipc_mean ipc_stddev ipc_min ipc_max \
             branch_mean branch_stddev branch_min branch_max \
             tlb_mean tlb_stddev tlb_min tlb_max \
             llc_mean llc_stddev llc_min llc_max \
             l1d_mean l1d_stddev l1d_min l1d_max \
             <<< $(awk '{
                ipc[NR]=$1; branch[NR]=$2; tlb[NR]=$3; llc[NR]=$4; l1d[NR]=$5;
                ipc_sum+=$1; branch_sum+=$2; tlb_sum+=$3; llc_sum+=$4; l1d_sum+=$5;
            } END {
                n=NR;
                ipc_avg=ipc_sum/n; branch_avg=branch_sum/n; tlb_avg=tlb_sum/n; llc_avg=llc_sum/n; l1d_avg=l1d_sum/n;

                ipc_min=ipc[1]; ipc_max=ipc[1];
                branch_min=branch[1]; branch_max=branch[1];
                tlb_min=tlb[1]; tlb_max=tlb[1];
                llc_min=llc[1]; llc_max=llc[1];
                l1d_min=l1d[1]; l1d_max=l1d[1];

                for(i=1;i<=n;i++) {
                    ipc_var += (ipc[i]-ipc_avg)^2;
                    branch_var += (branch[i]-branch_avg)^2;
                    tlb_var += (tlb[i]-tlb_avg)^2;
                    llc_var += (llc[i]-llc_avg)^2;
                    l1d_var += (l1d[i]-l1d_avg)^2;

                    if(ipc[i]<ipc_min) ipc_min=ipc[i]; if(ipc[i]>ipc_max) ipc_max=ipc[i];
                    if(branch[i]<branch_min) branch_min=branch[i]; if(branch[i]>branch_max) branch_max=branch[i];
                    if(tlb[i]<tlb_min) tlb_min=tlb[i]; if(tlb[i]>tlb_max) tlb_max=tlb[i];
                    if(llc[i]<llc_min) llc_min=llc[i]; if(llc[i]>llc_max) llc_max=llc[i];
                    if(l1d[i]<l1d_min) l1d_min=l1d[i]; if(l1d[i]>l1d_max) l1d_max=l1d[i];
                }

                printf "%.2f %.2f %.2f %.2f ", ipc_avg, sqrt(ipc_var/n), ipc_min, ipc_max;
                printf "%.2f %.2f %.2f %.2f ", branch_avg, sqrt(branch_var/n), branch_min, branch_max;
                printf "%.2f %.2f %.2f %.2f ", tlb_avg, sqrt(tlb_var/n), tlb_min, tlb_max;
                printf "%.2f %.2f %.2f %.2f ", llc_avg, sqrt(llc_var/n), llc_min, llc_max;
                printf "%.2f %.2f %.2f %.2f\n", l1d_avg, sqrt(l1d_var/n), l1d_min, l1d_max;
            }' "${log_file}.perf_samples")

        rm -f "${log_file}.perf_samples"
    else
        read ipc_mean branch_mean tlb_mean llc_mean l1d_mean <<< $(get_perf_stats)
        ipc_stddev=0; ipc_min=$ipc_mean; ipc_max=$ipc_mean;
        branch_stddev=0; branch_min=$branch_mean; branch_max=$branch_mean;
        tlb_stddev=0; tlb_min=$tlb_mean; tlb_max=$tlb_mean;
        llc_stddev=0; llc_min=$llc_mean; llc_max=$llc_mean;
        l1d_stddev=0; l1d_min=$l1d_mean; l1d_max=$l1d_mean;
    fi

    printf '{"type": "perf_stats", "ipc": {"mean": %s, "stddev": %s, "min": %s, "max": %s}, "branch_miss_rate": {"mean": %s, "stddev": %s, "min": %s, "max": %s}, "dTLB_miss_rate": {"mean": %s, "stddev": %s, "min": %s, "max": %s}, "llc_miss_rate": {"mean": %s, "stddev": %s, "min": %s, "max": %s}, "l1d_miss_rate": {"mean": %s, "stddev": %s, "min": %s, "max": %s}}\n' \
        "$ipc_mean" "$ipc_stddev" "$ipc_min" "$ipc_max" \
        "$branch_mean" "$branch_stddev" "$branch_min" "$branch_max" \
        "$tlb_mean" "$tlb_stddev" "$tlb_min" "$tlb_max" \
        "$llc_mean" "$llc_stddev" "$llc_min" "$llc_max" \
        "$l1d_mean" "$l1d_stddev" "$l1d_min" "$l1d_max" >> "$log_file"

    echo -e "${GREEN}IPC: ${ipc_mean}±${ipc_stddev} (${ipc_min}-${ipc_max}) | Branch Miss: ${branch_mean}±${branch_stddev}% | LLC Miss: ${llc_mean}±${llc_stddev}%${NC}"
}

run_monitor_internal() {
    local duration=$1
    local name=$2
    local log_file=$3
    local interval=2

    echo 1 > /proc/sys/kernel/bpf_stats_enabled 2>/dev/null || true

    printf '{"type": "header", "scheduler": "scx_imperator", "mode": "%s", "duration": %d, "timestamp": "%s", "kernel": "%s", "host": "%s"}\n' \
        "$name" "$duration" "$(date -Iseconds)" "$(uname -r)" "$(hostname)" > "$log_file"

    declare -A prev_bpf_cnt prev_bpf_time
    local prev_cs=0 prev_intr=0

    local bpf_stats_init=$(get_bpf_stats)
    while IFS=' ' read -r n x j rc rt; do
        [ -z "$n" ] && continue
        prev_bpf_cnt[$n]=$rc
        prev_bpf_time[$n]=$rt
    done <<< "$bpf_stats_init"
    read prev_cs prev_intr <<< "$(get_cs_stats)"
    read prev_res prev_loc prev_tlb <<< "$(get_interrupt_stats)"

    # Snapshot imperator_stats baseline for delta calculation
    read prev_new_flow prev_old_flow \
         prev_t0 prev_t1 prev_t2 prev_t3 \
         prev_s0 prev_s1 prev_s2 prev_s3 \
         prev_lock_skip prev_irq_boost prev_waker_boost \
         <<< "$(get_imperator_stats)"

    local end_time=$(($(date +%s) + duration))

    (
        while [ $(date +%s) -lt $end_time ]; do
            read ipc branch tlb llc l1d <<< $(get_perf_stats)
            echo "$ipc $branch $tlb $llc $l1d" >> "${log_file}.perf_samples"
            sleep 1
        done
    ) &
    local perf_pid=$!

    local samples=$((duration / interval))
    [ $samples -lt 1 ] && samples=1

    # Tier names match stats.rs: Critical(<100µs) Interactive(<2ms) Frame(<8ms) Bulk(≥8ms)
    local -a TIER_NAMES=("Critical" "Interactive" "Frame" "Bulk")

    for ((i=1; i<=samples; i++)); do
        sleep $interval

        local timestamp=$(date +%s)
        local bpf_stats=$(get_bpf_stats)
        read cs intr <<< "$(get_cs_stats)"
        read res loc tlb <<< "$(get_interrupt_stats)"
        read load1 load5 load15 runnable <<< "$(get_load)"
        local freq=$(get_cpu_freq)
        local binary_size=$(get_binary_size)

        # Imperator scheduler stats (deltas since last sample)
        read new_flow old_flow t0 t1 t2 t3 s0 s1 s2 s3 lock_skip irq_boost waker_boost \
            <<< "$(get_imperator_stats)"

        local d_new_flow=$(( new_flow - prev_new_flow ))
        local d_old_flow=$(( old_flow - prev_old_flow ))
        local d_t0=$(( t0 - prev_t0 ))
        local d_t1=$(( t1 - prev_t1 ))
        local d_t2=$(( t2 - prev_t2 ))
        local d_t3=$(( t3 - prev_t3 ))
        local d_s0=$(( s0 - prev_s0 ))
        local d_s1=$(( s1 - prev_s1 ))
        local d_s2=$(( s2 - prev_s2 ))
        local d_s3=$(( s3 - prev_s3 ))
        local d_lock_skip=$(( lock_skip - prev_lock_skip ))
        local d_irq_boost=$(( irq_boost - prev_irq_boost ))
        local d_waker_boost=$(( waker_boost - prev_waker_boost ))

        prev_new_flow=$new_flow; prev_old_flow=$old_flow
        prev_t0=$t0; prev_t1=$t1; prev_t2=$t2; prev_t3=$t3
        prev_s0=$s0; prev_s1=$s1; prev_s2=$s2; prev_s3=$s3
        prev_lock_skip=$lock_skip; prev_irq_boost=$irq_boost; prev_waker_boost=$waker_boost

        local cs_per_sec=$(( (cs - prev_cs) / interval ))
        local intr_per_sec=$(( (intr - prev_intr) / interval ))
        local res_per_sec=$(( (res - prev_res) / interval ))
        local loc_per_sec=$(( (loc - prev_loc) / interval ))
        local tlb_per_sec=$(( (tlb - prev_tlb) / interval ))

        prev_cs=$cs; prev_intr=$intr
        prev_res=$res; prev_loc=$loc; prev_tlb=$tlb

        # Compute tier dispatch rates per second
        local total_dispatches=$(( d_t0 + d_t1 + d_t2 + d_t3 ))
        local t0_rate=$(( d_t0 / interval ))
        local t1_rate=$(( d_t1 / interval ))
        local t2_rate=$(( d_t2 / interval ))
        local t3_rate=$(( d_t3 / interval ))

        # Build TUI output
        local buffer=""
        buffer+="\n${BOLD}System Metrics:${NC}\n"
        buffer+=$(printf "  CS: %d/s  |  Interrupts: %d/s  (RES: %d, LOC: %d)\n" "$cs_per_sec" "$intr_per_sec" "$res_per_sec" "$loc_per_sec")
        buffer+=$(printf "  CPU: %d MHz  |  Load: %.2f %.2f %.2f  |  Runnable: %s\n" "$freq" "$load1" "$load5" "$load15" "$runnable")

        # 4-tier dispatch breakdown (matches imperator_tier enum / TIER_NAMES in stats.rs)
        buffer+="\n${BOLD}Tier Dispatch Rates (dispatches/sec):${NC}\n"
        buffer+=$(printf "  T0 %-11s (<%4s µs): %6d/s  |  Starvation preempts: %d\n" "${TIER_NAMES[0]}" "100"  "$t0_rate" "$(( d_s0 / interval ))")
        buffer+=$(printf "  T1 %-11s (<  2 ms): %6d/s  |  Starvation preempts: %d\n" "${TIER_NAMES[1]}"        "$t1_rate" "$(( d_s1 / interval ))")
        buffer+=$(printf "  T2 %-11s (<  8 ms): %6d/s  |  Starvation preempts: %d\n" "${TIER_NAMES[2]}"        "$t2_rate" "$(( d_s2 / interval ))")
        buffer+=$(printf "  T3 %-11s (>= 8 ms): %6d/s  |  Starvation preempts: %d\n" "${TIER_NAMES[3]}"        "$t3_rate" "$(( d_s3 / interval ))")

        # Flow and scheduler event counters
        buffer+="\n${BOLD}Scheduler Events (per interval):${NC}\n"
        buffer+=$(printf "  New-flow dispatches: %d  |  Old-flow dispatches: %d\n" "$d_new_flow" "$d_old_flow")
        buffer+=$(printf "  Lock-holder skips:   %d  |  IRQ-wake boosts: %d  |  Waker-tier boosts: %d\n" \
            "$d_lock_skip" "$d_irq_boost" "$d_waker_boost")

        # BPF function overhead table
        buffer+="\n${BOLD}BPF Functions:${NC}\n"
        buffer+=$(printf "  %-18s %10s %10s %10s\n" "Function" "Calls/sec" "ns/call" "~Cycles")

        local total_overhead=0
        local total_jit=0
        local json_bpf_stats=""

        while IFS=' ' read -r fname xlated jited run_cnt run_time; do
            [ -z "$fname" ] && continue
            total_jit=$((total_jit + jited))

            local p_cnt=${prev_bpf_cnt[$fname]:-$run_cnt}
            local p_time=${prev_bpf_time[$fname]:-$run_time}

            local d_cnt=$((run_cnt - p_cnt))
            local d_time=$((run_time - p_time))

            local calls=0 ns_call=0 cycles=0
            if [ $d_cnt -gt 0 ]; then
                calls=$((d_cnt / interval))
                ns_call=$((d_time / d_cnt))
                cycles=$((ns_call * 5))
            fi

            total_overhead=$((total_overhead + (calls * ns_call)))

            if [ $cycles -lt 100 ]; then color=$GREEN
            elif [ $cycles -gt 500 ]; then color=$RED
            else color=$YELLOW; fi

            buffer+=$(printf "  ${CYAN}%-18s${NC} %10d %10d %10d\n" "$fname" "$calls" "$ns_call" "$cycles")

            if [ -n "$json_bpf_stats" ]; then json_bpf_stats+=", "; fi
            json_bpf_stats+=$(printf '"%s": {"cnt": %d, "ns": %d, "cycles": %d}' "$fname" "$calls" "$ns_call" "$cycles")

            prev_bpf_cnt[$fname]=$run_cnt
            prev_bpf_time[$fname]=$run_time
        done <<< "$bpf_stats"

        local overhead_hundredths=$((total_overhead / 100000))
        local overhead_pct="$((overhead_hundredths / 100)).$((overhead_hundredths % 100))"

        buffer+="\n${BOLD}Scheduler Overhead: ${CYAN}${overhead_pct}%%${NC} of 1 core\n"

        print_monitor_header "$interval"
        echo -e "$buffer"

        # JSON log line includes tier stats alongside existing fields
        printf '{"type": "sample", "seq": %d, "timestamp": %d, "metrics": {"context_switches_sec": %d, "interrupts_sec": %d, "interrupts_breakdown": {"res": %d, "loc": %d, "tlb": %d}, "cpu_freq_mhz": %d, "load_avg": [%s, %s, %s], "runnable_tasks": "%s"}, "tier_dispatches_sec": {"critical": %d, "interactive": %d, "frame": %d, "bulk": %d}, "starvation_preempts_sec": {"critical": %d, "interactive": %d, "frame": %d, "bulk": %d}, "scheduler_events": {"new_flow": %d, "old_flow": %d, "lock_holder_skips": %d, "irq_wake_boosts": %d, "waker_tier_boosts": %d}, "bpf_stats": {%s}, "overhead_pct": %s}\n' \
            "$i" "$timestamp" "$cs_per_sec" "$intr_per_sec" "$res_per_sec" "$loc_per_sec" "$tlb_per_sec" \
            "$freq" "$load1" "$load5" "$load15" "$runnable" \
            "$t0_rate" "$t1_rate" "$t2_rate" "$t3_rate" \
            "$(( d_s0 / interval ))" "$(( d_s1 / interval ))" "$(( d_s2 / interval ))" "$(( d_s3 / interval ))" \
            "$d_new_flow" "$d_old_flow" "$d_lock_skip" "$d_irq_boost" "$d_waker_boost" \
            "$json_bpf_stats" "$overhead_pct" >> "$log_file"
    done

    wait $perf_pid 2>/dev/null || true

    echo -e "${CYAN}Calculating statistics from ${duration} perf samples...${NC}"

    if [ -f "${log_file}.perf_samples" ]; then
        read ipc_mean ipc_stddev ipc_min ipc_max \
             branch_mean branch_stddev branch_min branch_max \
             tlb_mean tlb_stddev tlb_min tlb_max \
             llc_mean llc_stddev llc_min llc_max \
             l1d_mean l1d_stddev l1d_min l1d_max \
             <<< $(awk '{
                ipc[NR]=$1; branch[NR]=$2; tlb[NR]=$3; llc[NR]=$4; l1d[NR]=$5;
                ipc_sum+=$1; branch_sum+=$2; tlb_sum+=$3; llc_sum+=$4; l1d_sum+=$5;
            } END {
                n=NR;
                ipc_avg=ipc_sum/n; branch_avg=branch_sum/n; tlb_avg=tlb_sum/n; llc_avg=llc_sum/n; l1d_avg=l1d_sum/n;

                ipc_min=ipc[1]; ipc_max=ipc[1];
                branch_min=branch[1]; branch_max=branch[1];
                tlb_min=tlb[1]; tlb_max=tlb[1];
                llc_min=llc[1]; llc_max=llc[1];
                l1d_min=l1d[1]; l1d_max=l1d[1];

                for(i=1;i<=n;i++) {
                    ipc_var += (ipc[i]-ipc_avg)^2;
                    branch_var += (branch[i]-branch_avg)^2;
                    tlb_var += (tlb[i]-tlb_avg)^2;
                    llc_var += (llc[i]-llc_avg)^2;
                    l1d_var += (l1d[i]-l1d_avg)^2;

                    if(ipc[i]<ipc_min) ipc_min=ipc[i]; if(ipc[i]>ipc_max) ipc_max=ipc[i];
                    if(branch[i]<branch_min) branch_min=branch[i]; if(branch[i]>branch_max) branch_max=branch[i];
                    if(tlb[i]<tlb_min) tlb_min=tlb[i]; if(tlb[i]>tlb_max) tlb_max=tlb[i];
                    if(llc[i]<llc_min) llc_min=llc[i]; if(llc[i]>llc_max) llc_max=llc[i];
                    if(l1d[i]<l1d_min) l1d_min=l1d[i]; if(l1d[i]>l1d_max) l1d_max=l1d[i];
                }

                printf "%.2f %.2f %.2f %.2f ", ipc_avg, sqrt(ipc_var/n), ipc_min, ipc_max;
                printf "%.2f %.2f %.2f %.2f ", branch_avg, sqrt(branch_var/n), branch_min, branch_max;
                printf "%.2f %.2f %.2f %.2f ", tlb_avg, sqrt(tlb_var/n), tlb_min, tlb_max;
                printf "%.2f %.2f %.2f %.2f ", llc_avg, sqrt(llc_var/n), llc_min, llc_max;
                printf "%.2f %.2f %.2f %.2f\n", l1d_avg, sqrt(l1d_var/n), l1d_min, l1d_max;
            }' "${log_file}.perf_samples")

        rm -f "${log_file}.perf_samples"
    else
        read ipc_mean branch_mean tlb_mean llc_mean l1d_mean <<< $(get_perf_stats)
        ipc_stddev=0; ipc_min=$ipc_mean; ipc_max=$ipc_mean;
        branch_stddev=0; branch_min=$branch_mean; branch_max=$branch_mean;
        tlb_stddev=0; tlb_min=$tlb_mean; tlb_max=$tlb_mean;
        llc_stddev=0; llc_min=$llc_mean; llc_max=$llc_mean;
        l1d_stddev=0; l1d_min=$l1d_mean; l1d_max=$l1d_mean;
    fi

    echo ""
    echo -e "${BOLD}${GREEN}Performance Stats (${duration} samples):${NC}"
    echo -e "  IPC: ${CYAN}${ipc_mean} ± ${ipc_stddev}${NC} (range: ${ipc_min}-${ipc_max})"
    echo -e "  Branch Miss: ${YELLOW}${branch_mean} ± ${branch_stddev}%${NC} (range: ${branch_min}-${branch_max}%)"
    echo -e "  LLC Miss: ${YELLOW}${llc_mean} ± ${llc_stddev}%${NC} (range: ${llc_min}-${llc_max}%)"
    echo -e "  L1D Miss: ${YELLOW}${l1d_mean} ± ${l1d_stddev}%${NC} (range: ${l1d_min}-${l1d_max}%)"

    printf '{"type": "perf_stats", "ipc": {"mean": %s, "stddev": %s, "min": %s, "max": %s}, "branch_miss_rate": {"mean": %s, "stddev": %s, "min": %s, "max": %s}, "dTLB_miss_rate": {"mean": %s, "stddev": %s, "min": %s, "max": %s}, "llc_miss_rate": {"mean": %s, "stddev": %s, "min": %s, "max": %s}, "l1d_miss_rate": {"mean": %s, "stddev": %s, "min": %s, "max": %s}}\n' \
        "$ipc_mean" "$ipc_stddev" "$ipc_min" "$ipc_max" \
        "$branch_mean" "$branch_stddev" "$branch_min" "$branch_max" \
        "$tlb_mean" "$tlb_stddev" "$tlb_min" "$tlb_max" \
        "$llc_mean" "$llc_stddev" "$llc_min" "$llc_max" \
        "$l1d_mean" "$l1d_stddev" "$l1d_min" "$l1d_max" >> "$log_file"
}


# =============================================================================
# Control Functions
# =============================================================================

get_scheduler() {
    local sched
    sched=$(cat /sys/kernel/sched_ext/root/ops 2>/dev/null || echo "")
    if [ -z "$sched" ]; then
        echo "EEVDF"
    else
        echo "scx_$sched"
    fi
}

stop_scx() {
    if pgrep scx_imperator >/dev/null; then
        echo -e "${YELLOW}Stopping scx_imperator...${NC}"
        pkill -SIGINT scx_imperator || true
        sleep 2
        if pgrep scx_imperator >/dev/null; then
            pkill -9 scx_imperator || true
            sleep 1
        fi
    fi
}

start_scx() {
    if ! pgrep scx_imperator >/dev/null; then
        echo -e "${GREEN}Starting scx_imperator...${NC}"
        if [ ! -f "$START_SCRIPT" ]; then
            echo -e "${RED}Error: start.sh not found at $START_SCRIPT${NC}"
            return 1
        fi

        nohup "$START_SCRIPT" >/dev/null 2>&1 &
        sleep 2
        if ! pgrep scx_imperator >/dev/null; then
            echo -e "${RED}Failed to start scx_imperator! Check logs.${NC}"
            read -p "Press Enter to continue..."
            return 1
        fi
        echo -e "${GREEN}scx_imperator started successfully.${NC}"
    else
        echo -e "${GREEN}scx_imperator is already running.${NC}"
    fi
    return 0
}

run_capture_wrapper() {
    local duration=$1
    local name=$2
    local scheduler=$(get_scheduler)
    local log_file="$LOG_DIR/${name}_${scheduler}_$(date +%Y%m%d_%H%M%S).jsonl"

    echo -e "${BOLD}Running capture for ${CYAN}${duration}s${NC} on ${YELLOW}${scheduler}${NC}..."
    echo -e "${DIM}Log: $log_file${NC}"

    if [[ "$scheduler" == "EEVDF" ]]; then
        run_baseline_internal "$duration" "$name" "$log_file"
    else
        run_monitor_internal "$duration" "$name" "$log_file"
    fi

    echo -e "${GREEN}Capture complete!${NC}"
    echo "LOG_FILE=$log_file"
}

compare_logs() {
    local log1=$1
    local log2=$2

    echo -e "${BOLD}${MAGENTA}Comparison Summary:${NC}"
    echo -e "${DIM}Extracting key metrics (Context Switches, Overhead, Cache Misses, Tier Distribution)${NC}"
    echo ""

    echo -e "${BOLD}Baseline (EEVDF):${NC}"
    local cs_avg_1=$(awk '/"context_switches_sec":/ {sum+=$6; count++} END {if (count>0) print int(sum/count)}' "$log1" | tr -d ',')
    local ipc_1=$(grep '"ipc"' "$log1" | sed 's/.*"mean": \([0-9.]*\).*/\1/' | head -1)
    local branch_miss_1=$(grep '"branch_miss_rate"' "$log1" | sed 's/.*"mean": \([0-9.]*\).*/\1/' | head -1)
    local l1_miss_1=$(grep '"l1d_miss_rate"' "$log1" | sed 's/.*"mean": \([0-9.]*\).*/\1/' | head -1)
    local llc_miss_1=$(grep '"llc_miss_rate"' "$log1" | sed 's/.*"mean": \([0-9.]*\).*/\1/' | head -1)
    local res_avg_1=$(awk '/"res":/ {sum+=$3; count++} END {if (count>0) print int(sum/count)}' "$log1" | tr -d ',')

    echo "  Context Switches: ${cs_avg_1}/sec"
    echo "  Resched IRQs:     ${res_avg_1}/sec"
    echo "  IPC:              ${ipc_1}"
    echo "  Branch Miss Rate: ${branch_miss_1}%"
    echo "  L1D Miss Rate:    ${l1_miss_1}%"
    echo "  LLC Miss Rate:    ${llc_miss_1}%"

    echo ""
    echo -e "${BOLD}scx_imperator:${NC}"

    local cs_avg_2=$(awk '/"context_switches_sec":/ {sum+=$6; count++} END {if (count>0) print int(sum/count)}' "$log2" | tr -d ',')
    local overhead_2=$(awk '/"overhead_pct":/ {sum+=$NF; count++} END {if (count>0) print sum/count}' "$log2" | tr -d '}')
    local ipc_2=$(grep '"ipc"' "$log2" | sed 's/.*"mean": \([0-9.]*\).*/\1/' | head -1)
    local branch_miss_2=$(grep '"branch_miss_rate"' "$log2" | sed 's/.*"mean": \([0-9.]*\).*/\1/' | head -1)
    local l1_miss_2=$(grep '"l1d_miss_rate"' "$log2" | sed 's/.*"mean": \([0-9.]*\).*/\1/' | head -1)
    local llc_miss_2=$(grep '"llc_miss_rate"' "$log2" | sed 's/.*"mean": \([0-9.]*\).*/\1/' | head -1)
    local res_avg_2=$(awk '/"res":/ {sum+=$3; count++} END {if (count>0) print int(sum/count)}' "$log2" | tr -d ',')

    # Tier dispatch averages from imperator log
    local t0_avg=$(awk '/"critical":/ {sum+=$2; count++} END {if(count>0) print int(sum/count)}' "$log2" | tr -d ',')
    local t1_avg=$(awk '/"interactive":/ {sum+=$2; count++} END {if(count>0) print int(sum/count)}' "$log2" | tr -d ',')
    local t2_avg=$(awk '/"frame":/ {sum+=$2; count++} END {if(count>0) print int(sum/count)}' "$log2" | tr -d ',')
    local t3_avg=$(awk '/"bulk":/ {sum+=$2; count++} END {if(count>0) print int(sum/count)}' "$log2" | tr -d ',')

    # Scheduler event totals from imperator log
    local irq_total=$(awk '/"irq_wake_boosts":/ {sum+=$2; count++} END {if(count>0) print int(sum)}' "$log2" | tr -d ',')
    local waker_total=$(awk '/"waker_tier_boosts":/ {sum+=$2; count++} END {if(count>0) print int(sum)}' "$log2" | tr -d ',')
    local lock_total=$(awk '/"lock_holder_skips":/ {sum+=$2; count++} END {if(count>0) print int(sum)}' "$log2" | tr -d ',')

    echo "  Context Switches:   ${cs_avg_2}/sec"
    echo "  Resched IRQs:       ${res_avg_2}/sec"
    echo "  Scheduler Overhead: ${overhead_2}%"
    echo "  IPC:                ${ipc_2}"
    echo "  Branch Miss Rate:   ${branch_miss_2}%"
    echo "  L1D Miss Rate:      ${l1_miss_2}%"
    echo "  LLC Miss Rate:      ${llc_miss_2}%"
    echo ""
    echo -e "  ${BOLD}Tier Dispatch Rates (avg dispatches/sec):${NC}"
    echo "    T0 Critical    (<100 µs): ${t0_avg}/s"
    echo "    T1 Interactive (<  2 ms): ${t1_avg}/s"
    echo "    T2 Frame       (<  8 ms): ${t2_avg}/s"
    echo "    T3 Bulk        (>= 8 ms): ${t3_avg}/s"
    echo ""
    echo -e "  ${BOLD}Scheduler Events (totals):${NC}"
    echo "    IRQ-wake boosts:    ${irq_total}"
    echo "    Waker-tier boosts:  ${waker_total}"
    echo "    Lock-holder skips:  ${lock_total}"

    echo ""
}

# =============================================================================
# Main Menu
# =============================================================================

# Headless Mode Support
if [ "$1" == "--headless" ]; then
    workload_opt=$2
    target_opt=$3

    echo "Running in headless mode: Workload=$workload_opt Target=$target_opt"

    case $workload_opt in
        1) DURATION=5;  SUFFIX="quick"   ;;
        2) DURATION=15; SUFFIX="desktop" ;;
        3) DURATION=30; SUFFIX="gaming"  ;;
        4) DURATION=60; SUFFIX="stress"  ;;
        *) echo "Invalid headless workload"; exit 1 ;;
    esac

    case $target_opt in
        3)
            start_scx || exit 1
            run_capture_wrapper "$DURATION" "$SUFFIX"
            exit 0
            ;;
        *) echo "Headless target not supported (only 3: scx_imperator)"; exit 1 ;;
    esac
fi

while true; do
    print_menu_header
    CURRENT_SCHED=$(get_scheduler)
    echo -e "Current Scheduler: ${YELLOW}$CURRENT_SCHED${NC}"
    echo ""
    echo "Please select a benchmark workload:"
    echo -e "  ${BOLD}1)${NC} Quick Check    (5s)"
    echo -e "  ${BOLD}2)${NC} Desktop Usage  (15s)"
    echo -e "  ${BOLD}3)${NC} Gaming Session (30s)"
    echo -e "  ${BOLD}4)${NC} Stress Test    (60s)"
    echo -e "  ${BOLD}5)${NC} Custom Duration"
    echo -e "  ${BOLD}q)${NC} Quit"
    echo ""
    read -p "Select option: " workload_opt

    case $workload_opt in
        1) DURATION=5;  SUFFIX="quick"   ;;
        2) DURATION=15; SUFFIX="desktop" ;;
        3) DURATION=30; SUFFIX="gaming"  ;;
        4) DURATION=60; SUFFIX="stress"  ;;
        5) read -p "Enter duration (seconds): " DURATION; SUFFIX="custom" ;;
        q|Q) exit 0 ;;
        *) echo "Invalid option"; sleep 1; continue ;;
    esac

    echo ""
    echo "Select Benchmark Target:"
    echo -e "  ${BOLD}1)${NC} Current Scheduler (Run on $CURRENT_SCHED)"
    echo -e "  ${BOLD}2)${NC} Baseline Only (Force EEVDF)"
    echo -e "  ${BOLD}3)${NC} scx_imperator Only (Force Load)"
    echo -e "  ${BOLD}4)${NC} Compare (Baseline vs scx_imperator)"
    echo -e "  ${BOLD}b)${NC} Back"
    echo ""
    read -p "Select target: " target_opt

    case $target_opt in
        1)
            run_capture_wrapper "$DURATION" "$SUFFIX"
            read -p "Press Enter to continue..."
            ;;
        2)
            stop_scx
            run_capture_wrapper "$DURATION" "$SUFFIX"
            read -p "Press Enter to continue..."
            ;;
        3)
            start_scx || continue
            run_capture_wrapper "$DURATION" "$SUFFIX"
            read -p "Press Enter to continue..."
            ;;
        4)
            echo -e "\n${BOLD}${MAGENTA}Phase 1: Baseline (EEVDF)${NC}"
            stop_scx
            echo -e "${YELLOW}Scheduler unloaded. Prepare for baseline capture in 3s...${NC}"
            sleep 3
            output1=$(run_capture_wrapper "$DURATION" "${SUFFIX}_baseline")
            log1=$(echo "$output1" | grep "LOG_FILE=" | cut -d= -f2 | tr -d '[:space:]')

            echo -e "\n${BOLD}${MAGENTA}Phase 2: scx_imperator${NC}"
            start_scx || continue
            echo -e "${YELLOW}Scheduler loaded. Prepare for scx_imperator capture in 3s...${NC}"
            sleep 3
            output2=$(run_capture_wrapper "$DURATION" "${SUFFIX}_scx_imperator")
            log2=$(echo "$output2" | grep "LOG_FILE=" | cut -d= -f2 | tr -d '[:space:]')

            if [ -f "$log1" ] && [ -f "$log2" ]; then
                compare_logs "$log1" "$log2"
            else
                echo -e "${RED}Error: Could not find logs for comparison.${NC}"
            fi

            read -p "Press Enter to continue..."
            ;;
        b|B) continue ;;
        *) echo "Invalid option"; sleep 1; continue ;;
    esac
done
