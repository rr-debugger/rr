#include <assert.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/user.h>

#include "recorder.h"
#include "write_trace.h"
#include "../share/ipc.h"
#include "../share/util.h"
#include "../share/trace.h"
#include "../share/sys.h"
#include "../share/hpc.h"

static __inline__ unsigned long long rdtsc(void)
{
	unsigned hi, lo;
	__asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
	return ((unsigned long long) lo) | (((unsigned long long) hi) << 32);
}

static int handle_sigsegv(struct context *ctx)
{
	pid_t tid = ctx->child_tid;
	int sig = signal_pending(ctx->status);

	if (sig <= 0 || sig != SIGSEGV) {
		return 0;
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
	} else {
		return 0;
	}
	free(inst);

	return 1;
}

void handle_signal(struct context* ctx)
{
	int sig = signal_pending(ctx->status);

	if (sig <= 0) {
		return;
	}

	switch (sig) {

	case SIGALRM:
	case SIGCHLD:
	{
		ctx->event = -sig;
		ctx->child_sig = sig;
		break;
	}


	case SIGSEGV:
	{
		if (handle_sigsegv(ctx)) {
			ctx->event = SIG_SEGV_RDTSC;
			ctx->child_sig = 0;
		} else {
			printf("we got a SIGSEGV(11)\n");
			ctx->event = -sig;
			ctx->child_sig = sig;
		}
		break;
	}

	case SIGIO:
	{
		assert(1==0);
		/* make sure that the signal came from hpc */
		if (read_rbc_up(ctx->hpc) >= MAX_RECORD_INTERVAL) {
			ctx->event = USR_SCHED;
		} else {
			ctx->event = -sig;
			ctx->child_sig = sig;
		}
		break;
	}

	default:
	fprintf(stderr, "signal %d not implemented yet -- bailing out\n", sig);

	sys_exit();
		break;
	}
}
