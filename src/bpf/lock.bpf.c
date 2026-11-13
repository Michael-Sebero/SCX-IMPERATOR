/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_imperator: lock-holder detection (adapted from scx_lavd lock.bpf.c).
 *
 * Built as part of imperator.bpf.c, which #includes this file at the end, so
 * the probes share task_ctx, mega_mailbox and the helpers without cross-object
 * linking. Up to Gen 5 this file was never compiled at all: build.rs only
 * builds imperator.bpf.c and nothing included it.
 *
 * Every program is SEC("?...") (not auto-loaded). The loader enables one set
 * at open time and attaches it after load (main.rs, --lock-boost):
 *   fexit       — fexit probes on the in-kernel futex functions (preferred,
 *                 cheapest; needs BTF for those functions and ftrace)
 *   tracepoint  — syscalls:sys_{enter,exit}_futex* tracepoints (fallback)
 *
 * MODEL (LAVD's, with bounds):
 *   acquired  futex_wait/futex_waitv/futex_wait_requeue_pi returning a wake,
 *             futex_lock_pi succeeding
 *               → CAKE_FLAG_LOCK_HOLDER on the task, and this CPU's
 *                 mega_mailbox.lock_since = now
 *   released  futex_wake / futex_wake_op / futex_unlock_pi
 *               → both cleared
 *   stopping  → both cleared; a task switched out while still holding the
 *               flag (preempted or slice-expired) gets CAKE_XF_LOCK_BOOST,
 *               a one-shot within-tier deadline advance on its re-queue
 *
 * While the flag is set and the lock is younger than LOCK_WINDOW_NS
 * (quantum/4), the CPU is skipped as a T0/T1 preemption victim and
 * ops.dispatch keeps the task running for one LOCK_WINDOW_NS extension past
 * its slice. The window bound exists because futex_wait() returning 0 means
 * "woken", which is also what a condvar or job-queue waiter sees: LAVD keeps
 * such a task protected until it calls futex_wake or stops, which can cover a
 * long CPU-bound run.
 *
 * Coverage: uncontended locks never enter the kernel and are invisible here.
 * FUTEX_WAIT_REQUEUE_PI returns only once the waiter owns the PI mutex, so it
 * is covered, flagged when the waiter's own call returns.
 */

static __always_inline void lock_acquired(void)
{
    struct task_struct *p = bpf_get_current_task_btf();
    struct imperator_task_ctx *tctx = bpf_task_storage_get(&task_ctx, p, 0, 0);

    /* No context: not a sched_ext task (RT/DL, or not yet enabled). */
    if (!tctx)
        return;

    if (!(imperator_relaxed_load_u32(&tctx->packed_info) & FLOWFLAG(CAKE_FLAG_LOCK_HOLDER)))
        __sync_fetch_and_or(&tctx->packed_info, FLOWFLAG(CAKE_FLAG_LOCK_HOLDER));

    /* The futex call returns on the CPU the task is running on, so this is
     * the owning CPU's own mailbox. */
    u32 cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
    u32 now = (u32)scx_bpf_now();
    imperator_relaxed_store_u32(&mega_mailbox[cpu].lock_since, now ? now : 1);
}

static __always_inline void lock_released(void)
{
    struct task_struct *p = bpf_get_current_task_btf();
    struct imperator_task_ctx *tctx = bpf_task_storage_get(&task_ctx, p, 0, 0);

    if (!tctx)
        return;

    if (imperator_relaxed_load_u32(&tctx->packed_info) & FLOWFLAG(CAKE_FLAG_LOCK_HOLDER)) {
        __sync_fetch_and_and(&tctx->packed_info, ~FLOWFLAG(CAKE_FLAG_LOCK_HOLDER));
        u32 cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
        imperator_relaxed_store_u32(&mega_mailbox[cpu].lock_since, 0);
    }
}

/* ── fexit probes ─────────────────────────────────────────────────────────
 * Declared without arguments and read the return value with
 * bpf_get_func_ret(), so they do not depend on each function's parameter
 * list (which has changed across kernel versions). */

/* int __futex_wait(u32 *uaddr, unsigned int flags, u32 val,
 *                  struct hrtimer_sleeper *to, u32 bitset)  — 0 when woken */
SEC("?fexit/__futex_wait")
int BPF_PROG(imperator_fexit_futex_wait)
{
    u64 ret = 0;
    bpf_get_func_ret(ctx, &ret);
    if ((s32)ret == 0)
        lock_acquired();
    return 0;
}

/* futex_waitv(2), used by Proton's fsync: returns the index of the futex
 * that woke the task, or a negative error. */
SEC("?fexit/futex_wait_multiple")
int BPF_PROG(imperator_fexit_futex_wait_multiple)
{
    u64 ret = 0;
    bpf_get_func_ret(ctx, &ret);
    if ((s32)ret >= 0)
        lock_acquired();
    return 0;
}

SEC("?fexit/futex_wait_requeue_pi")
int BPF_PROG(imperator_fexit_futex_wait_requeue_pi)
{
    u64 ret = 0;
    bpf_get_func_ret(ctx, &ret);
    if ((s32)ret == 0)
        lock_acquired();
    return 0;
}

SEC("?fexit/futex_lock_pi")
int BPF_PROG(imperator_fexit_futex_lock_pi)
{
    u64 ret = 0;
    bpf_get_func_ret(ctx, &ret);
    if ((s32)ret == 0)
        lock_acquired();
    return 0;
}

/* Returns the number of waiters woken (>= 0). */
SEC("?fexit/futex_wake")
int BPF_PROG(imperator_fexit_futex_wake)
{
    u64 ret = 0;
    bpf_get_func_ret(ctx, &ret);
    if ((s32)ret >= 0)
        lock_released();
    return 0;
}

SEC("?fexit/futex_wake_op")
int BPF_PROG(imperator_fexit_futex_wake_op)
{
    u64 ret = 0;
    bpf_get_func_ret(ctx, &ret);
    if ((s32)ret >= 0)
        lock_released();
    return 0;
}

SEC("?fexit/futex_unlock_pi")
int BPF_PROG(imperator_fexit_futex_unlock_pi)
{
    u64 ret = 0;
    bpf_get_func_ret(ctx, &ret);
    if ((s32)ret == 0)
        lock_released();
    return 0;
}

/* ── tracepoint fallback ──────────────────────────────────────────────────
 * Layouts follow /sys/kernel/tracing/events/syscalls/<event>/format: an
 * 8-byte trace_entry, the int syscall number, then one 8-byte slot per
 * argument. (The Gen 5 structs put 16 bytes in front of __syscall_nr and
 * read every field 8 bytes late; they were never loaded.) */
#define CAKE_FUTEX_WAIT            0
#define CAKE_FUTEX_WAKE            1
#define CAKE_FUTEX_WAKE_OP         5
#define CAKE_FUTEX_LOCK_PI         6
#define CAKE_FUTEX_UNLOCK_PI       7
#define CAKE_FUTEX_TRYLOCK_PI      8
#define CAKE_FUTEX_WAIT_BITSET     9
#define CAKE_FUTEX_WAKE_BITSET     10
#define CAKE_FUTEX_WAIT_REQUEUE_PI 11
#define CAKE_FUTEX_LOCK_PI2        13
#define CAKE_FUTEX_PRIVATE_FLAG    128
#define CAKE_FUTEX_CLOCK_RT        256
#define CAKE_FUTEX_CMD_MASK        (~(CAKE_FUTEX_PRIVATE_FLAG | CAKE_FUTEX_CLOCK_RT))

struct tp_imperator_futex_enter {
    struct trace_entry ent;
    int __syscall_nr;
    u32 *uaddr;
    int op;
};

struct tp_imperator_syscall_exit {
    struct trace_entry ent;
    int __syscall_nr;
    long ret;
};

/* The op is recorded per task (not per CPU): a blocking futex call can
 * return on a different CPU than it entered on. */
SEC("?tracepoint/syscalls/sys_enter_futex")
int imperator_tp_enter_futex(struct tp_imperator_futex_enter *ctx)
{
    struct task_struct *p = bpf_get_current_task_btf();
    struct imperator_task_ctx *tctx = bpf_task_storage_get(&task_ctx, p, 0, 0);

    if (tctx)
        tctx->pending_futex_op = (u8)(ctx->op & CAKE_FUTEX_CMD_MASK);
    return 0;
}

SEC("?tracepoint/syscalls/sys_exit_futex")
int imperator_tp_exit_futex(struct tp_imperator_syscall_exit *ctx)
{
    struct task_struct *p = bpf_get_current_task_btf();
    struct imperator_task_ctx *tctx = bpf_task_storage_get(&task_ctx, p, 0, 0);
    long ret = ctx->ret;

    /* CAKE_FUTEX_OP_UNSET until a sys_enter_futex was seen for this task. */
    if (!tctx || tctx->pending_futex_op == CAKE_FUTEX_OP_UNSET)
        return 0;

    switch (tctx->pending_futex_op) {
    case CAKE_FUTEX_WAIT:
    case CAKE_FUTEX_WAIT_BITSET:
    case CAKE_FUTEX_WAIT_REQUEUE_PI:
    case CAKE_FUTEX_LOCK_PI:
    case CAKE_FUTEX_LOCK_PI2:
    case CAKE_FUTEX_TRYLOCK_PI:
        if (ret == 0)
            lock_acquired();
        break;
    case CAKE_FUTEX_WAKE:
    case CAKE_FUTEX_WAKE_BITSET:
    case CAKE_FUTEX_WAKE_OP:
        if (ret >= 0)
            lock_released();
        break;
    case CAKE_FUTEX_UNLOCK_PI:
        if (ret == 0)
            lock_released();
        break;
    }

    tctx->pending_futex_op = CAKE_FUTEX_OP_UNSET;
    return 0;
}

/* futex2 syscalls (6.7+: futex_wait/futex_wake; 5.16+: futex_waitv). */
SEC("?tracepoint/syscalls/sys_exit_futex_wait")
int imperator_tp_exit_futex_wait(struct tp_imperator_syscall_exit *ctx)
{
    if (ctx->ret == 0)
        lock_acquired();
    return 0;
}

SEC("?tracepoint/syscalls/sys_exit_futex_waitv")
int imperator_tp_exit_futex_waitv(struct tp_imperator_syscall_exit *ctx)
{
    if (ctx->ret >= 0)
        lock_acquired();
    return 0;
}

SEC("?tracepoint/syscalls/sys_exit_futex_wake")
int imperator_tp_exit_futex_wake(struct tp_imperator_syscall_exit *ctx)
{
    if (ctx->ret >= 0)
        lock_released();
    return 0;
}
