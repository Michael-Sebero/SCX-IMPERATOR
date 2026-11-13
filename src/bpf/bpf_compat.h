/* scx_imperator/bpf/bpf_compat.h */
#ifndef __CAKE_BPF_COMPAT_H
#define __CAKE_BPF_COMPAT_H

/* Compiler abstraction: Clang 21+ uses formal atomics for MLP; <21 uses scalpel-optimized ASM */

#if defined(__clang__) && __clang_major__ >= 21

    /* MODERN PATH: Formal Atomics (Max Performance) */
    #define imperator_relaxed_load_u8(ptr)       __atomic_load_n(ptr, __ATOMIC_RELAXED)
    #define imperator_relaxed_store_u8(ptr, v)   __atomic_store_n(ptr, v, __ATOMIC_RELAXED)
    #define imperator_relaxed_load_u32(ptr)      __atomic_load_n(ptr, __ATOMIC_RELAXED)
    #define imperator_relaxed_store_u32(ptr, v)  __atomic_store_n(ptr, v, __ATOMIC_RELAXED)
    #define imperator_relaxed_load_u64(ptr)      __atomic_load_n(ptr, __ATOMIC_RELAXED)
    #define imperator_relaxed_store_u64(ptr, v)  __atomic_store_n(ptr, v, __ATOMIC_RELAXED)

#else

    /* COMPAT PATH: Scalpel-Optimized Inline Assembly */

    /* FIX (audit): u8 atomic helpers — prevents compiler from emitting non-atomic
     * byte stores/loads on weakly-ordered architectures (ARM64).  Plain struct
     * member assignment is not guaranteed to be atomic or visible to other CPUs
     * without these wrappers, which is a data race under the C11 memory model.
     * Used for mega_mailbox u8 fields (flags, dsq_hint) that are
     * written by the owning CPU in imperator_tick and read by other CPUs in imperator_enqueue
     * (waker-tier inheritance).  RELAXED semantics are sufficient here: no ordering
     * with respect to surrounding memory operations is required — visibility alone
     * is the goal.  __ATOMIC_RELAXED maps to a plain MOV on both x86 and ARM64;
     * the "m"(*ptr) memory operand tells the compiler the location is live. */
    static __always_inline u8 imperator_relaxed_load_u8(const volatile u8 *ptr) {
        u8 val;
        asm volatile(
            "%0 = *(u8 *)(%1 + 0)"
            : "=r"(val)
            : "r"(ptr), "m"(*ptr)
        );
        return val;
    }

    static __always_inline void imperator_relaxed_store_u8(volatile u8 *ptr, u8 val) {
        asm volatile(
            "*(u8 *)(%1 + 0) = %2"
            : "=m"(*ptr)
            : "r"(ptr), "r"(val)
        );
    }

    static __always_inline u32 imperator_relaxed_load_u32(const volatile u32 *ptr) {
        u32 val;
        asm volatile(
            "%0 = *(u32 *)(%1 + 0)"
            : "=r"(val)
            : "r"(ptr), "m"(*ptr)  /* Targeted dependency, no global spill */
        );
        return val;
    }

    static __always_inline void imperator_relaxed_store_u32(volatile u32 *ptr, u32 val) {
        asm volatile(
            "*(u32 *)(%1 + 0) = %2"
            : "=m"(*ptr)           /* Only this address modified */
            : "r"(ptr), "r"(val)
        );
    }

    static __always_inline u64 imperator_relaxed_load_u64(const volatile u64 *ptr) {
        u64 val;
        asm volatile(
            "%0 = *(u64 *)(%1 + 0)"
            : "=r"(val)
            : "r"(ptr), "m"(*ptr)
        );
        return val;
    }

    static __always_inline void imperator_relaxed_store_u64(volatile u64 *ptr, u64 val) {
        asm volatile(
            "*(u64 *)(%1 + 0) = %2"
            : "=m"(*ptr)
            : "r"(ptr), "r"(val)
        );
    }

#endif

/* Bitfield extraction: shift + mask (2 cycles) — BMI2 BEXTR unavailable in BPF ISA */
#define EXTRACT_BITS_U32(val, start, len) \
    (((u32)(val) >> (start)) & ((1U << (len)) - 1))
#define EXTRACT_BITS_U64(val, start, len) \
    (((u64)(val) >> (start)) & ((1ULL << (len)) - 1))

/* BIT SCAN FORWARD (CTZ): Clang <19 fallback uses De Bruijn to avoid opcode 191 crash */
#if defined(__clang__) && __clang_major__ < 19
    static __always_inline u32 imperator_ctz64(u64 mask, u64 mult) {
        static const u8 de_bruijn_bits[64] = {
            0,  1,  2, 53,  3,  7, 54, 27, 4, 38, 41,  8, 34, 55, 48, 28,
            62, 5, 39, 46, 44, 42, 22,  9, 24, 35, 59, 56, 49, 18, 29, 11,
            63, 52, 6, 26, 37, 40, 33, 47, 61, 45, 43, 21, 23, 58, 17, 10,
            51, 25, 36, 32, 60, 20, 57, 16, 50, 31, 19, 15, 30, 14, 13, 12
        };

        u64 lsb = mask & -mask;

        /* FIX (barrier-placement): Barrier after the multiply, not after lsb.
         * The previous `asm volatile("" : "+r"(lsb))` blocked CSE on lsb itself
         * but left the multiply→shift→table-index chain visible to LLVM's post-RA
         * peephole pass, which can re-derive lsb from the still-live mask register
         * and then recognise the complete De Bruijn pattern, replacing it with
         * __builtin_ctzll.  On Clang 18 with -O2 this emits BPF opcode 191, which
         * crashes hardware JITs that do not implement it.  Placing the barrier after
         * `product` forces the compiler to materialise the multiply result as a
         * named register before the barrier, breaking the chain at the only point
         * where a peephole rewrite is profitable. */
        u64 product = lsb * mult;
        asm volatile("" : "+r"(product));

        return de_bruijn_bits[product >> 58];
    }
    #define BIT_SCAN_FORWARD_U64(mask) imperator_ctz64(mask, 0x022FDD63CC95386DULL)

    /* FIX (#15): U32-specific BSF using De Bruijn sequence for 32-bit masks.
     * Avoids zero-extending u32 into the 64-bit De Bruijn table which uses a
     * 64-bit multiplier — correct by accident but semantically wrong. */
    static __always_inline u32 imperator_ctz32(u32 mask) {
        static const u8 de_bruijn32[32] = {
            0, 1, 28, 2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17, 4, 8,
            31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18, 6, 11, 5, 10, 9
        };
        u32 lsb = mask & (u32)(-(s32)mask);
        /* FIX (barrier-placement): Barrier after the multiply — see imperator_ctz64
         * comment.  Materialises the product register before the peephole window,
         * preventing Clang 18 post-RA from recovering the De Bruijn sequence and
         * substituting __builtin_ctz (which emits opcode 191 on older JITs). */
        u32 product = lsb * 0x077CB531U;
        asm volatile("" : "+r"(product));
        return de_bruijn32[product >> 27];
    }
    #define BIT_SCAN_FORWARD_U32(mask) imperator_ctz32(mask)
#else
    #define BIT_SCAN_FORWARD_U64(mask) __builtin_ctzll(mask)
    /* FIX (#15): Use __builtin_ctz for u32 operands (correct width, avoids implicit widening) */
    #define BIT_SCAN_FORWARD_U32(mask) __builtin_ctz(mask)
#endif

/* rq access: the imperator_get_rq() wrapper around scx_bpf_cpu_rq() was
 * removed in Gen 6. scx_bpf_cpu_rq() is deprecated upstream (use
 * scx_bpf_locked_rq() for the rq the kernel already holds, or
 * __COMPAT_scx_bpf_cpu_curr() for a remote CPU's current task), and its only
 * caller was imperator_tick's unreachable Phase 2 starvation check. */

/* ═══════════════════════════════════════════════════════════════════════════
 * IRQ CONTEXT DETECTION (Gen 6 — from scx bpf_experimental.h, as used by LAVD)
 *
 * Up to Gen 5 this file declared bpf_in_hardirq/bpf_in_nmi/
 * bpf_in_serving_softirq as __weak kfuncs. No mainline kernel exports kfuncs
 * by those names — in the scx tree they are inline helpers reading the
 * per-CPU preempt count — so the weak symbols resolved to NULL, every check
 * read false, and the IRQ-wake boost only ever fired for wakeups issued by
 * ksoftirqd.
 *
 * These read the preempt count directly: the per-CPU __preempt_count on
 * x86 (6.15+), pcpu_hot.preempt_count between 6.1 and 6.14, and the task's
 * thread_info on arm64. On PREEMPT_RT, softirqs run in task context and are
 * tracked in task_struct::softirq_disable_cnt instead. Elsewhere they read 0
 * (no boost), as before.
 * ═══════════════════════════════════════════════════════════════════════════ */
#define IMP_SOFTIRQ_SHIFT   8
#define IMP_HARDIRQ_SHIFT   16
#define IMP_NMI_SHIFT       20
#define IMP_SOFTIRQ_MASK    (0xffUL << IMP_SOFTIRQ_SHIFT)
#define IMP_HARDIRQ_MASK    (0x0fUL << IMP_HARDIRQ_SHIFT)
#define IMP_NMI_MASK        (0x0fUL << IMP_NMI_SHIFT)
#define IMP_SOFTIRQ_OFFSET  (1UL << IMP_SOFTIRQ_SHIFT)

extern bool CONFIG_PREEMPT_RT __kconfig __weak;

#if defined(bpf_target_x86)
extern const int __preempt_count __ksym __weak;

struct pcpu_hot___imperator {
    int preempt_count;
} __attribute__((preserve_access_index));

extern struct pcpu_hot___imperator pcpu_hot __ksym __weak;
#endif

struct task_struct___imperator_rt {
    int softirq_disable_cnt;
} __attribute__((preserve_access_index));

static __always_inline int imperator_preempt_count(void)
{
#if defined(bpf_target_x86)
    if (bpf_ksym_exists(&__preempt_count))
        return *(int *)bpf_this_cpu_ptr(&__preempt_count);
    if (bpf_core_field_exists(pcpu_hot.preempt_count))
        return ((struct pcpu_hot___imperator *)bpf_this_cpu_ptr(&pcpu_hot))->preempt_count;
#elif defined(bpf_target_arm64)
    return bpf_get_current_task_btf()->thread_info.preempt.count;
#endif
    return 0;
}

/* Hard IRQ or NMI: device interrupts and, on non-RT kernels, every hrtimer
 * expiry (nanosleep, futex/poll/epoll timeouts, timerfd). */
static __always_inline bool imperator_in_hardirq_or_nmi(void)
{
    return imperator_preempt_count() & (IMP_HARDIRQ_MASK | IMP_NMI_MASK);
}

/* Serving a softirq (network RX, block completion, timer_list). */
static __always_inline bool imperator_in_serving_softirq(void)
{
    if (!CONFIG_PREEMPT_RT)
        return (imperator_preempt_count() & IMP_SOFTIRQ_MASK) & IMP_SOFTIRQ_OFFSET;

    struct task_struct___imperator_rt *tsk = (void *)bpf_get_current_task_btf();
    return (tsk->softirq_disable_cnt & IMP_SOFTIRQ_MASK) & IMP_SOFTIRQ_OFFSET;
}

#endif /* __CAKE_BPF_COMPAT_H */
