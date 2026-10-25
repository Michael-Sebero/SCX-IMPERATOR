#!/bin/bash
# Build script for scx_imperator
#
# Builds one binary per AMD CPU generation. Both are compiled for the
# x86-64-v4 level (x86-64-v3 plus AVX-512 F/BW/CD/DQ/VL). Zen 4 was AMD's first
# generation with AVX-512, so every Zen 4 and Zen 5 CPU supports it:
#
#   scx_imperator_z4   -C target-cpu=x86-64-v4   Zen 4 (also runs on Zen 5)
#   scx_imperator_z5   -C target-cpu=x86-64-v4   Zen 5 (also runs on Zen 4)
#
# This script used to build with -C target-cpu=native, i.e. "tune for whatever
# CPU runs the build". Built on Zen 5, such a binary can contain Zen 5-only
# instructions (AVX-VNNI, AVX512_VP2INTERSECT, MOVDIRI, MOVDIR64B, PREFETCHI)
# and then dies with "Illegal instruction" on Zen 4.
#
#   * x86-64-v4 is a fixed instruction-set level, so the result does not depend
#     on the machine that runs the build, and the compiler has no Zen 5-only
#     instructions to choose from. After each build the binary is disassembled,
#     and the build FAILS if one slipped in anyway (e.g. through
#     CFLAGS=-march=native).
#   * Variants with the same target-cpu are compiled once and the result is
#     copied, so with the settings above the second variant built is just a copy
#     of the first. Give a variant its own target-cpu in cpu_for() below and it
#     gets its own compile again.
#   * The scheduler logic itself is BPF code (the -mcpu=v4 in build.rs is the BPF
#     instruction-set version, not an x86 CPU) which the kernel JIT-compiles at
#     load time. These builds only change the userspace loader and TUI.
#
# Usage:
#   ./build.sh                    build both
#   ./build.sh z4                 build only scx_imperator_z4
#   ./build.sh z5                 build only scx_imperator_z5
#   ./build.sh z4 --features foo  anything after the variant goes to `cargo build`
#
# Output: ./target/release/scx_imperator_z4 and ./target/release/scx_imperator_z5
# (start.sh picks the right one for the CPU it runs on)

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

TARGET_BASE="${CARGO_TARGET_DIR:-./target}"
OUT_DIR="${TARGET_BASE}/release"

usage() {
    echo "Usage: ./build.sh [z4] [z5] [cargo args...]"
    echo "  z4   build scx_imperator_z4 (x86-64-v4; runs on Zen 4 and Zen 5)"
    echo "  z5   build scx_imperator_z5 (x86-64-v4; runs on Zen 4 and Zen 5)"
    echo "  no variant given = build both"
}

VARIANTS=()
while (( $# )); do
    case "$1" in
        z4|z5)      VARIANTS+=("$1") ;;
        all)        VARIANTS+=(z4 z5) ;;
        -h|--help)  usage; exit 0 ;;
        *)          break ;;
    esac
    shift
done
(( ${#VARIANTS[@]} )) || VARIANTS=(z4 z5)
CARGO_ARGS=("$@")

# Rust target-cpu for each variant. x86-64-v4 only needs AVX-512, which every
# Zen 4 and Zen 5 CPU has.
cpu_for() {
    case "$1" in
        z4) echo x86-64-v4 ;;
        z5) echo x86-64-v4 ;;
    esac
}

# --- Keep stray host-specific code out of the build ---------------------------
# CARGO_ENCODED_RUSTFLAGS would take priority over RUSTFLAGS, so clear it. Any
# RUSTFLAGS from the environment are kept, but our target-cpu goes last and wins
# over a stray "-C target-cpu=native". Setting RUSTFLAGS also makes cargo ignore
# rustflags from config files.
unset CARGO_ENCODED_RUSTFLAGS
BASE_RUSTFLAGS="${RUSTFLAGS:-}"

# C code built by dependencies (libbpf & co.) must not use -march=native either.
for var in CFLAGS CXXFLAGS; do
    if [[ -n "${!var:-}" ]]; then
        export "$var=$(sed -E 's/(^|[[:space:]])-m(arch|cpu)=[^[:space:]]+//g' <<<"${!var}")"
    fi
done

# --- Checks -------------------------------------------------------------------
# rustc silently falls back to generic code for a CPU name it does not know,
# which would leave a binary that is not really built for the CPU level you
# asked for.
check_rustc_knows() {
    local cpu="$1" cpus
    cpus="$("${RUSTC:-rustc}" --print target-cpus 2>/dev/null || true)"
    if ! grep -Eq "^[[:space:]]+${cpu}[[:space:]]*$" <<<"$cpus"; then
        echo "ERROR: your Rust/LLVM does not know target-cpu=${cpu}." >&2
        echo "       Update it, e.g.: rustup update stable" >&2
        exit 1
    fi
}

# cargo also compiles build scripts with these flags and runs them on THIS
# machine, so warn if this machine could not run code built for x86-64-v4.
warn_if_host_cannot_run() {
    [[ -r /proc/cpuinfo ]] || return 0
    local flag missing=()
    for flag in avx512f avx512bw avx512cd avx512dq avx512vl; do
        grep -qw "$flag" /proc/cpuinfo || missing+=("$flag")
    done
    if (( ${#missing[@]} )); then
        echo "WARNING: this machine has no ${missing[*]} (x86-64-v4 needs AVX-512), but cargo runs build scripts here compiled for x86-64-v4." >&2
        echo "         If the build dies with 'Illegal instruction', build on a Zen 4/5 (or other AVX-512) machine." >&2
    fi
}

# Mnemonics that exist on Zen 5 but not on Zen 4, matched in `objdump -d` output.
# AVX-VNNI (VEX-encoded, c4/c5 prefix byte) is told apart from the Zen 4-safe
# AVX512-VNNI (EVEX, 62 prefix) by its encoding, not by how objdump labels it.
TAB=$'\t'
ZEN5_ONLY="${TAB}(vp2intersect[dq]|movdiri|movdir64b|prefetchit[01])[[:space:]]"
ZEN5_ONLY+="|${TAB}(c4|c5)( [0-9a-f]{2})+ *${TAB}(\{vex\} )?vpdp(bus|wss)ds?[[:space:]]"

check_no_zen5_only_code() {
    local bin="$1" asm hits="" rc=0
    if ! command -v objdump >/dev/null 2>&1; then
        echo "NOTE: objdump (binutils) not found - skipped the Zen 4 compatibility check." >&2
        return 0
    fi

    asm="$(mktemp)"
    objdump -d "$bin" > "$asm" 2>/dev/null || rc=$?
    if (( rc == 0 )); then
        hits="$(grep -E "$ZEN5_ONLY" "$asm" | head -n 5 || true)"
    fi
    rm -f "$asm"

    if (( rc != 0 )); then
        echo "NOTE: objdump could not read $bin - skipped the Zen 4 compatibility check." >&2
        return 0
    fi
    if [[ -n "$hits" ]]; then
        echo "ERROR: $bin contains Zen 5-only instructions and would crash on Zen 4:" >&2
        echo "$hits" >&2
        echo "       Look for -march=native / -C target-cpu=native in RUSTFLAGS, CFLAGS or build scripts." >&2
        return 1
    fi
    echo "OK: no Zen 5-only instructions in $(basename "$bin") - safe on Zen 4 and Zen 5."
}

# --- Build --------------------------------------------------------------------
# Each variant gets its own cargo target dir: the CPU flags apply to every crate,
# so sharing one dir would rebuild everything each time the variant changes.
declare -A BUILT_AS=()    # target-cpu -> binary already built with it in this run

build_variant() {
    local name="$1" cpu out
    cpu="$(cpu_for "$name")"
    out="${OUT_DIR}/scx_imperator_${name}"

    # Same target-cpu means same flags means the same binary: copy the one that
    # was already built in this run instead of compiling it a second time.
    if [[ -n "${BUILT_AS[$cpu]:-}" ]]; then
        echo "=== scx_imperator_${name} (target-cpu=${cpu}): same build as $(basename "${BUILT_AS[$cpu]}"), copying it ==="
        install -D -m 755 "${BUILT_AS[$cpu]}" "$out"
        return 0
    fi

    check_rustc_knows "$cpu"
    warn_if_host_cannot_run

    echo "=== Building scx_imperator_${name} (target-cpu=${cpu}) ==="
    CARGO_TARGET_DIR="${TARGET_BASE}/${name}" \
    RUSTFLAGS="${BASE_RUSTFLAGS} -C target-cpu=${cpu}" \
        cargo build --release "${CARGO_ARGS[@]}"

    install -D -m 755 "${TARGET_BASE}/${name}/release/scx_imperator" "$out"

    # Only a Zen 5-only build (target-cpu=znver5) may use Zen 5-only
    # instructions; every other build has to run on Zen 4 too.
    if [[ "$cpu" != znver5 ]]; then
        check_no_zen5_only_code "$out"
    fi

    BUILT_AS[$cpu]="$out"
}

if (( ${#VARIANTS[@]} > 1 )); then
    echo "Building ${#VARIANTS[@]} variants; the first run compiles every crate once per distinct target-cpu."
fi
for v in "${VARIANTS[@]}"; do
    build_variant "$v"
done

echo ""
echo "=== Build complete ==="
for v in "${VARIANTS[@]}"; do
    echo "  ${OUT_DIR}/scx_imperator_${v}   target-cpu=$(cpu_for "$v")"
done
if [[ -e "${OUT_DIR}/scx_imperator" ]]; then
    echo ""
    echo "NOTE: ${OUT_DIR}/scx_imperator was not made by this script (probably an older"
    echo "      native build) and may crash on other CPUs - share the _z4/_z5 files instead."
fi
echo ""
echo "Run with: sudo ./start.sh   (picks the right build for this CPU)"
