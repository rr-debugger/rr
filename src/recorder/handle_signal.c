#include <assert.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <fcntl.h>

#include <sys/mman.h>
#include <sys/user.h>

#include "recorder.h"

#include "../share/dbg.h"
#include "../share/ipc.h"
#include "../share/util.h"
#include "../share/trace.h"
#include "../share/sys.h"
#include "../share/hpc.h"
#include "../share/wrap_syscalls.h"

static __inline__ unsigned long long rdtsc(void)
{
	unsigned hi, lo;
	__asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
	return ((unsigned long long) lo) | (((unsigned long long) hi) << 32);
}

static int handle_sigsegv(struct context *ctx)
{
	int retval = 0;
	pid_t tid = ctx->child_tid;
	int sig = signal_pending(ctx->status);

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
	}

	sys_free(&inst);

	return retval;
}

static int handle_mmap_sigsegv(struct context *ctx)
{
	pid_t tid = ctx->child_tid;
	int sig = signal_pending(ctx->status);

	if (sig <= 0 || sig != SIGSEGV) {
		return 0;
	}

	// locate the offending address
	siginfo_t si;
	sys_ptrace_getsiginfo(ctx->child_tid,&si);
	void* addr = si.si_addr;

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

static void record_signal(int sig, struct context* ctx)
{
	record_event(ctx, STATE_SYSCALL_ENTRY);
	reset_hpc(ctx, MAX_RECORD_INTERVAL); // TODO: the hpc gets reset in record event.
	assert(read_insts(ctx->hpc) == 0);
	// enter the sig handler
	sys_ptrace_singlestep(ctx->child_tid, sig);
	// wait for the kernel to finish setting up the handler
	sys_waitpid(ctx->child_tid, &(ctx->status));
	// 0 instructions means we entered a handler
	int insts = read_insts(ctx->hpc);
	size_t frame_size = 0;
	if (insts == 0)
		frame_size = 1024; // TODO: find out actual struct sigframe size. 128 seems to be too small
	struct user_regs_struct regs;
	read_child_registers(ctx->child_tid, &regs);
	/*
	// this is an attempt to figure out if a signal handler exists and
	// act according to it, but it does not fully function.
	struct sigaction* action = get_sig_handler(ctx->child_tid, sig);
	struct user_regs_struct regs;
	size_t frame_size = 0;
	// only if a signal handler is installed
	if (action) {
		assert(!(action->sa_flags & SA_RESETHAND));
		// enter the sig handler
		sys_ptrace_singlestep(ctx->child_tid, sig);
		// wait for the kernel to finish setting up the handler
		sys_waitpid(ctx->child_tid, &(ctx->status));
		read_child_registers(ctx->child_tid, &regs);
		// if a sighandler was installed, we should be at its entry point now
		assert((void*)regs.eip == action->sa_handler);
		// record the frame
		frame_size = 1024;
	} else {
		read_child_registers(ctx->child_tid, &regs);
	}
	*/
	record_child_data(ctx, -sig, frame_size, regs.esp);
}

void handle_signal(struct context* ctx)
{
	int sig = signal_pending(ctx->status);

	if (sig <= 0) {
		return;
	}

	debug("handling signal %d", sig);

	/* Received a signal in the critical section of recording a wrapped syscall */
	while (WRAP_SYSCALLS_CALLSITE_IN_WRAPPER(ctx->child_regs.eip,ctx)) {
		/* Delay delivery of the signal until we are out of it */
		log_info("Got signal %d while in lib, singelestepping, eip = %p",sig,ctx->child_regs.eip);
		sys_ptrace_singlestep(ctx->child_tid,0);
		sys_waitpid(ctx->child_tid, &ctx->status);
		read_child_registers(ctx->child_tid, &(ctx->child_regs));
	}

	switch (sig) {

	case SIGALRM:
	case SIGTERM:
	case SIGPIPE:
	case SIGWINCH:
	case SIGCHLD:
	case 33: /* SIGRTMIN + 1 */
	case 62: /* SIGRTMAX - 1 */
	{
		ctx->event = -sig;
		ctx->child_sig = sig;
		record_signal(sig, ctx);
		break;
	}

	case SIGSEGV:
	{
		int mmap_event = 0;
		if (handle_sigsegv(ctx)) { // RDTSC
			ctx->event = SIG_SEGV_RDTSC;
			ctx->child_sig = 0;
		} else if ((mmap_event = handle_mmap_sigsegv(ctx)) != 0) { // accessing a shared region
			ctx->event = mmap_event;
			ctx->child_sig = 0;
		} else {
			ctx->event = -sig;
			ctx->child_sig = sig;
			record_signal(sig, ctx);
		}
		break;
	}

	case SIGIO:
	{
		/* make sure that the signal came from hpc */
		if (read_rbc(ctx->hpc) >= MAX_RECORD_INTERVAL) {
			ctx->event = USR_SCHED;
			ctx->child_sig = 0;

			/* go to the next retired conditional branch; this position
			 * is certainly unambigious */
			/*uint64_t current_rbc = read_rbc_up(ctx->hpc);
			uint64_t stop_rbc = current_rbc + 1;
			do {
				sys_ptrace_singlestep(ctx->child_tid, 0);
				sys_waitpid(ctx->child_tid, &(ctx->status));
				current_rbc = read_rbc_up(ctx->hpc);
			} while (current_rbc < stop_rbc);*/

		} else {
			ctx->event = -sig;
			ctx->child_sig = sig;
			record_signal(sig, ctx);
		}
		break;
	}

	default:
		log_err("signal %d not implemented yet -- bailing out\n", sig);
		sys_exit();
		break;
	}
}
