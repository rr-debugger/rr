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

static int handle_rdtsc(struct context* context)
{
	pid_t tid = context->child_tid;
	int sig = signal_pending(context->status);

	if (sig <= 0 || sig != SIGSEGV) {
		return 0;
	}

	int size;
	char* inst = get_inst(tid, 0, &size);

	if (strncmp(inst, "rdtsc", 5) == 0) {
		long int eax, edx;
		unsigned long long current_time;

		current_time = rdtsc();
		eax = current_time & 0xffffffff;
		edx = current_time >> 32;

		//record_timestamp(tid, &eax, &edx);
		struct user_regs_struct regs;
		read_child_registers(tid, &regs);
		regs.eax = eax;
		regs.edx = edx;
		regs.eip += size;
		write_child_registers(tid, &regs);
		context->event = SIG_SEGV_RDTSC;
	}
	free(inst);

	return 1;
}

void handle_signal(struct context* context)
{
	int sig = signal_pending(context->status);

	if (sig <= 0) {
		return;
	}

//	fprintf(stderr,"got signal: %d\n",sig);

	switch (sig) {

	case SIGALRM:
	case SIGCHLD:
	{
		context->pending_sig = sig;
		context->event = -sig;
		break;
	}

	case SIGSEGV:
	{
		if (handle_rdtsc(context)) {
			context->event = SIG_SEGV_RDTSC;
			context->pending_sig = 0;
			break;
		} else {
			assert(1==0);
		}
	}

	case SIGIO:
	{
		/* make sure that the signal came from hpc */
		if (read_rbc_up(context->hpc) >= MAX_RECORD_INTERVAL) {
			context->event = USR_SCHED;
		} else {
			context->pending_sig = sig;
			context->event = -sig;
		}
		break;
	}

	default:
	printf("signal %d not implemented yet -- bailing out\n", sig);
	sys_exit();
	}
}
