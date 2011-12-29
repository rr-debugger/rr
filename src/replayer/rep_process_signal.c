#include <assert.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <sys/fcntl.h>

#include "read_trace.h"
#include "replayer.h"

#include "../share/sys.h"
#include "../share/trace.h"
#include "../share/util.h"
#include "../share/ipc.h"
#include "../share/hpc.h"

#define SKID_SIZE 			50

/**
 * function goes to the n-th conditional branch
 */
static void compensate_branch_count(struct context *ctx)
{
	uint64_t rbc_now, rbc_rec;
	uint32_t offset = -1;

	rbc_now = read_rbc_up(ctx->hpc);
	rbc_rec = ctx->trace.rbc_up;

	/* if the skid size was too small, go back to the last checkpoint and
	 * re-execute the program.
	 */
	if (rbc_now > rbc_rec) {
		/* checkpointing is not implemented yet - so we fail */
		fprintf(stderr, "hpc overcounted in asynchronous event, recorded: %llu  now: %llu\n", rbc_rec, rbc_now);
		assert(rbc_now < rbc_rec);
	}

	while (1) {
		struct user_regs_struct regs;
		read_child_registers(ctx->child_tid, &regs);
		rbc_now = read_rbc_up(ctx->hpc);


		if (rbc_now < rbc_rec) {
			singlestep(ctx);
		} else if (rbc_now == rbc_rec) {
			if (!compare_register_files("now", &regs, "rec", &ctx->trace.recorded_regs, 0, 0)) {
				printf("yeah, we got it :-) offset: %u: rec was: %llu\n", offset, rbc_rec);
				break;
			}
			singlestep(ctx);
		} else {
			fprintf(stderr, "internal error: cannot find correct spot in compensate_branch_count -- bailing out\n");
			fprintf(stderr, "but we were right at offset: %u\n", offset);
			sys_exit();
		}
	}

	printf("time: %u\n",ctx->trace.global_time);
}

void rep_process_signal(struct context *ctx)
{
	struct trace* trace = &(ctx->trace);
	int tid = ctx->child_tid;
	int sig = -trace->stop_reason;

	switch (sig) {

	/* set the eax and edx register to the recorded values */
	case -SIG_SEGV_RDTSC:
	{
		struct user_regs_struct regs;
		int size;

		/* goto the event */
		goto_next_event(ctx);

		/* make sure we are there */
		assert(WSTOPSIG(ctx->status) == SIGSEGV);

		char* inst = get_inst(tid, 0, &size);
		assert(strncmp(inst,"rdtsc",5) == 0);
		read_child_registers(tid, &regs);
		regs.eax = trace->recorded_regs.eax;
		regs.edx = trace->recorded_regs.edx;
		regs.eip += size;
		write_child_registers(tid, &regs);
		sys_free((void**) &inst);

		compare_register_files("rdtsv_now", &regs, "rdsc_rec", &ctx->trace.recorded_regs, 1, 1);

		/* this signal should not be recognized by the application */
		ctx->pending_sig = 0;
		break;
	}

	case -USR_SCHED:
	{
		assert(trace->rbc_up > 0);

		/* if the current architecture over-counts the event in question,
		 * substract the overcount here */
		reset_hpc(ctx, trace->rbc_up - SKID_SIZE);
		goto_next_event(ctx);
		/* make sure that the signal came from hpc */
		if (fcntl(ctx->hpc->rbc_down.fd, F_GETOWN) == ctx->child_tid) {
			/* this signal should not be recognized by the application */
			ctx->pending_sig = 0;
			stop_hpc_down(ctx);
			compensate_branch_count(ctx);
			stop_hpc(ctx);
		} else {
			fprintf(stderr,"internal error: next event should be: %d but it is: %d -- bailing out\n",-USR_SCHED,ctx->event);
			sys_exit();
		}

		break;
	}

	case SIGIO:
	case SIGCHLD:
	{
		/* synchronous signal (signal received in a system call) */
		if (trace->rbc_up == 0) {
			ctx->pending_sig = sig;
			return;
		}

		assert(1==0);
		// setup and start replay counters
		reset_hpc(ctx, trace->rbc_up - SKID_SIZE);
		printf("setting replay counters: retired branch count = %llu\n", trace->rbc_up);
		// single-step if the number of instructions to the next event is "small"
		if (trace->rbc_up <= 100) {
			compensate_branch_count(ctx);
		} else {
			printf("large count\n");
			sys_ptrace_cont(tid);
			sys_waitpid(tid, &ctx->status);
			// make sure we ere interrupted by ptrace
			assert(WSTOPSIG(ctx->status) == SIGIO);

			compensate_branch_count(ctx);

		}

		break;
	}

	default:
	printf("unknown signal %d -- bailing out\n", sig);
	sys_exit();
	}
}
