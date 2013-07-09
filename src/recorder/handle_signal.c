/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "handle_signal.h"

#include <assert.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/mman.h>
#include <sys/user.h>

#include "recorder.h"

#include "../share/dbg.h"
#include "../share/ipc.h"
#include "../share/util.h"
#include "../share/trace.h"
#include "../share/sys.h"
#include "../share/hpc.h"
#include "../share/syscall_buffer.h"

static __inline__ unsigned long long rdtsc(void)
{
	unsigned hi, lo;
	__asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
	return ((unsigned long long) lo) | (((unsigned long long) hi) << 32);
}

/**
 * Return nonzero if |ctx| was stopped because of a SIGSEGV resulting
 * from a rdtsc and |ctx| was updated appropriately, zero otherwise.
 */
static int try_handle_rdtsc(struct context *ctx)
{
	int retval = 0;
	pid_t tid = ctx->child_tid;
	int sig = signal_pending(ctx->status);
	assert(sig != SIGTRAP);

	if (sig <= 0 || sig != SIGSEGV) {
		return retval;
	}

	int size;
	char *inst = get_inst(tid, 0, &size);

	/* if the current instruction is a rdtsc, the segfault was triggered by
	 * by reading the rdtsc instruction */
	if (strncmp(inst, "rdtsc", 5) == 0) {
		long int eax, edx;
		unsigned long long current_time;

		current_time = rdtsc();
		eax = current_time & 0xffffffff;
		edx = current_time >> 32;

		struct user_regs_struct regs;
		read_child_registers(tid, &regs);
		regs.eax = eax;
		regs.edx = edx;
		regs.eip += size;
		write_child_registers(tid, &regs);
		ctx->event = SIG_SEGV_RDTSC;
		retval = 1;

		debug("  trapped for rdtsc: returning %llu", current_time);
	}

	sys_free((void**)&inst);

	return retval;
}

/**
 * Return nonzero if |ctx| was stopped because of a SIGSEGV resulting
 * from access of a shared mmap and |ctx| was updated appropriately,
 * zero otherwise.
 */
static int try_handle_shared_mmap_access(struct context *ctx,
					 const siginfo_t* si)
{
	pid_t tid = ctx->child_tid;
	int sig = signal_pending(ctx->status);
	assert(sig != SIGTRAP);

	if (sig <= 0 || sig != SIGSEGV) {
		return 0;
	}

	// locate the offending address
	void* addr = si->si_addr;

	// check that its indeed in a shared mmaped region we previously protected
	if (!is_protected_map(ctx,addr)){
		return 0;
	}

	// get the type of the instruction
	int size;
	bool is_write = is_write_mem_instruction(tid, 0, &size);

	// since emulate_child_inst also advances the eip,
	// we need to record the event BEFORE the instruction is executed
	ctx->event = is_write ? SIG_SEGV_MMAP_WRITE : SIG_SEGV_MMAP_READ;
	emulate_child_inst(ctx,0);
	/*
	struct user_regs_struct regs;
	read_child_registers(tid, &regs);
	regs.eip += size;
	write_child_registers(tid, &regs);
	*/

	/*
	// unprotect the region and allow the instruction to run
	mprotect_child_region(ctx, addr, PROT_WRITE);
	sys_ptrace_singlestep(tid,0);

	if (!is_write) { // we only need to record on reads, writes are fine
		record_child_data(ctx,SIG_SEGV_MMAP_READ,get_mmaped_region_end(ctx,addr) - addr,addr);
	}

	// protect the region again
	mprotect_child_region(ctx, addr, PROT_NONE);
	 */
	return ctx->event;
}

static uint64_t
read_desched_counter(struct context* ctx)
{
	uint64_t nr_descheds;
	read(ctx->desched_fd, &nr_descheds, sizeof(nr_descheds));
	return nr_descheds;
}

/**
 * Return nonzero if |ctx| was stopped because of a SIGIO resulting
 * from notification of |ctx| being descheduled, zero otherwise.
 */
static int try_handle_desched_event(struct context* ctx, const siginfo_t* si)
{
	pid_t tid = ctx->child_tid;
	int call = ctx->event;
	uint64_t nr_descheds;
	int status;
	struct user_regs_struct regs;

	assert(SIGIO == si->si_signo);

	if (si->si_code != POLL_IN || si->si_fd != ctx->desched_fd_child) {
		debug("  (SIGIO not for desched: code=%d, fd=%d)",
		      si->si_code, si->si_fd);
		return 0;
	}

	/* TODO: how can signals interrupt us here? */

	/* Clear the pending input. */
	nr_descheds = read_desched_counter(ctx);
	debug("  (desched #%llu during `%s')", nr_descheds, syscallname(call));

	/* Disarm the counter to prevent further desched events while
	 * we're manipulating the tracee and it finishes its
	 * syscall. */
	if (ioctl(ctx->desched_fd, PERF_EVENT_IOC_DISABLE, 0)) {
		fatal("Failed to disarm desched event");
	}

	/* For not-perfectly-understood reasons, we see a second,
	 * redundant SIGIO notificaion (see syscall_buffer.c).  Step
	 * over the redundant one. */
	sys_ptrace_syscall(tid);
	sys_waitpid(tid, &status);
	assert(WIFSTOPPED(status) && SIGIO == WSTOPSIG(status)
	       && read_desched_counter(ctx) == nr_descheds);

	/* The next event is either a trace of entering the blocking
	 * syscall, or if the syscall has already finished, then a
	 * trace of the syscallbuf code entering the
	 * disarm_desched_event() ioctl. */
	sys_ptrace_syscall(tid);
	sys_waitpid(tid, &status);
	/* (syscall trap event) */
	assert(WIFSTOPPED(status) && (0x80 | SIGTRAP) == WSTOPSIG(status));

	read_child_registers(tid, &regs);
	/* XXX extra anal: check that $ip is at the untraced syscall
	 * entry */
	if (SYS_ioctl == regs.orig_eax
	    && regs.ebx == ctx->desched_fd_child
	    && PERF_EVENT_IOC_DISABLE == regs.ecx) {
		/* Finish the ioctl().  It won't block, and we don't
		 * need to record it or any other data for the replay
		 * to work properly.  The reason we can do this is
		 * that the replaying code doesn't need any trace data
		 * to know how to step over these ioctls.  And the
		 * syscall buffer must not be full (or we wouldn't
		 * have armed the desched event), so it doesn't need
		 * flushing.  The next traced event will flush the
		 * buffer normally. */
		sys_ptrace_syscall(tid);
		sys_waitpid(tid, &status);

		debug("  consumed unneeded desched event during `%s'",
		      syscallname(call));
		return USR_NOOP;
	}

	debug("  resuming (and probably switching out) blocked `%s'",
	      syscallname(call));

	if (SYS_restart_syscall == regs.orig_eax) {
		/* If we'll be resuming this as a "restart syscall",
		 * then note that the last started syscall was the one
		 * interrupted by desched. */
		ctx->last_syscall = call;
	}
	ctx->desched = 1;
	return call;
}

static int is_deterministic_signal(const siginfo_t* si)
{
	switch (si->si_signo) {
		/* These signals may be delivered deterministically;
		 * we'll check for sure below. */
	case SIGILL:
	case SIGTRAP:
	case SIGBUS:
	case SIGFPE:
	case SIGSEGV:
	case SIGSTKFLT:
		/* As bits/siginfo.h documents,
		 *
		 *   Values for `si_code'.  Positive values are
		 *   reserved for kernel-generated signals.
		 *
		 * So if the signal is maybe-synchronous, and the
		 * kernel delivered it, then it must have been
		 * delivered deterministically. */
		return si->si_code > 0;
	default:
		/* All other signals can never be delivered
		 * deterministically (to the approximation required by
		 * rr). */
		return 0;
	}

}

static void record_signal(int sig, struct context* ctx, const siginfo_t* si)
{
	ctx->child_sig = sig;

	if (is_deterministic_signal(si)) {
		ctx->event = -(sig | DET_SIGNAL_BIT);
	} else {
		ctx->event = -sig;
	}

	record_event(ctx, STATE_SYSCALL_ENTRY);
	reset_hpc(ctx, MAX_RECORD_INTERVAL); // TODO: the hpc gets reset in record event.
	assert(read_insts(ctx->hpc) == 0);
	// enter the sig handler
	sys_ptrace_singlestep_sig(ctx->child_tid, sig);
	// wait for the kernel to finish setting up the handler
	sys_waitpid(ctx->child_tid, &(ctx->status));
	// 0 instructions means we entered a handler
	int insts = read_insts(ctx->hpc);
	// TODO: find out actual struct sigframe size. 128 seems to be too small
	size_t frame_size = (insts == 0) ? 1024 : 0;
	struct user_regs_struct regs;
	read_child_registers(ctx->child_tid, &regs);
	record_child_data(ctx, ctx->event, frame_size, (void*)regs.esp);
}

void handle_signal(struct context* ctx)
{
	int sig = signal_pending(ctx->status);
	int event;
	siginfo_t si;

	if (sig <= 0) {
		return;
	}

	debug("handling signal %s (pevent: %d, event: %s)", signalname(sig),
	      GET_PTRACE_EVENT(ctx->status), strevent(ctx->event));

	sys_ptrace_getsiginfo(ctx->child_tid, &si);

	/* See if this signal occurred because of internal rr usage,
	 * and update ctx appropriately. */
	switch (sig) {
	case SIGSEGV: {
		int mmap_event;
		if (try_handle_rdtsc(ctx)) {
			ctx->event = SIG_SEGV_RDTSC;
			ctx->child_sig = 0;
			return;
		} else if ((mmap_event = try_handle_shared_mmap_access(ctx,
								       &si))) {
			ctx->event = mmap_event;
			ctx->child_sig = 0;
			return;
		}
		break;
	}
	case SIGIO:
		if ((event = try_handle_desched_event(ctx, &si))) {
			ctx->event = event;
			ctx->child_sig = 0;
			return;
		} else if (read_rbc(ctx->hpc) >= MAX_RECORD_INTERVAL) {
			/* HPC interrupt due to exceeding time
			 * slice. */
			ctx->event = USR_SCHED;
			ctx->child_sig = 0;
			return;
		}
	}

	/* This signal was generated by the program or an external
	 * source, record it normally. */
	record_signal(sig, ctx, &si);
}
