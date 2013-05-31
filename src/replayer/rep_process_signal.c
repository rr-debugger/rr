/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <assert.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <sys/fcntl.h>

#include "replayer.h"

#include "../share/sys.h"
#include "../share/trace.h"
#include "../share/util.h"
#include "../share/ipc.h"
#include "../share/hpc.h"
#include "../share/dbg.h"

#define SKID_SIZE 			55

static void singlestep(struct context *ctx, int sig, int expected_val)
{
	sys_ptrace_singlestep(ctx->child_tid, sig);
	sys_waitpid(ctx->child_tid, &ctx->status);
	/* we get a simple SIGTRAP in this case */
	if (ctx->status != expected_val) {
		log_err("status %x   expected %x\n", ctx->status, expected_val);
		// TODO: exit?
	}

	assert(ctx->status == expected_val);
	ctx->status = 0;
	ctx->child_sig = 0;
}

/**
 * finds the exact instruction on which the signal occured
 */
static void compensate_rbc_count(struct context *ctx, int sig)
{
	uint64_t rbc_now = read_rbc(ctx->hpc), rbc_rec = ctx->trace.rbc;

	/* TODO: attempt to place a breakpoint instead of single-stepping
	// put a breakpoint at the desired eip and wait for it
	char code[] = {0xcc};
	void * backup = read_child_data(ctx, 1, (void*)ctx->trace.recorded_regs.eip);

	while (read_rbc(ctx->hpc) < rbc_rec) {
		// put the breakpoint
		write_child_data(ctx, 1, (void*)ctx->trace.recorded_regs.eip, code);

		// run up to it
		sys_ptrace_cont(ctx->child_tid);
		sys_waitpid(ctx->child_tid, &ctx->status);

		// put back the code
		write_child_data(ctx, 1, (void*)ctx->trace.recorded_regs.eip, backup);

		// if we are not there yet, execute the instruction
		// TODO: this might mess up the perf counters
		if (read_rbc(ctx->hpc) < rbc_rec)
			singlestep(ctx, 0, 0x57f);
	}

	rbc_now = read_rbc(ctx->hpc);
	struct user_regs_struct regs;
	read_child_registers(ctx->child_tid, &regs);
	int check = compare_register_files("now", &regs, "rec", &ctx->trace.recorded_regs, 0, 0);

	// put back the code and finish
	write_child_data(ctx, 3, (void*)ctx->trace.recorded_regs.eip, backup);
	write_child_main_registers(ctx->child_tid, &ctx->trace.recorded_regs);
	sys_free(&backup);
	return;
	 */
	// check that we arrived at the exact instruction count

	/* if the skid size was too small, go back to the last checkpoint and
	 * re-execute the program.
	 */
	if (rbc_now > rbc_rec) {
		/* checkpointing is not implemented yet - so we fail */
		fprintf(stderr, "hpc overcounted in asynchronous event, recorded: %llu  now: %llu\n", rbc_rec, rbc_now);
		fprintf(stderr,"event: %d, flobal_time %u\n",ctx->trace.stop_reason, ctx->trace.global_time);
		assert(0);
	}

	int found_spot = 0;

	while (rbc_now < rbc_rec) {
		singlestep(ctx, 0, 0x57f);
		rbc_now = read_rbc(ctx->hpc);
	}

	while (rbc_now == rbc_rec) {
		struct user_regs_struct regs;
		read_child_registers(ctx->child_tid, &regs);
		if (sig == SIGSEGV) {
			/* we should now stop at the instruction that caused the SIGSEGV */
			sys_ptrace_syscall(ctx->child_tid);
			sys_waitpid(ctx->child_tid, &ctx->status);
		}

		/* the eflags register has two bits that are set when an interrupt is pending:
		 * bit 8:  TF (trap flag)
		 * bit 17: VM (virtual 8086 mode)
		 *
		 * we enable these two bits in the eflags register to make sure that the register
		 * files match
		 *
		 */
		int check = compare_register_files("signal single-stepping now", &regs, "rec", &ctx->trace.recorded_regs, 0, 0);
		if (check == 0 || check == 0x80) {
			found_spot++;
			/* A SIGSEGV can be triggered by a regular instruction; it is not necessarily sent by
			 * another process. We check this condition here.
			 */
			if (sig == SIGSEGV) {
				//print_inst(ctx->child_tid);

				/* here we ensure that the we get a SIGSEGV at the right spot */
				//singlestep(ctx, 0, 0xb7f);
				/* deliver the signal */
				break;
			} else {
				break;
			}
			/* set the signal such that it is delivered when the process continues */
		}
		/* check that we do not get unexpected signal in the single-stepping process */
		singlestep(ctx, 0, 0x57f); // TODO: MAGIC NUMBER MUCH?
		rbc_now = read_rbc(ctx->hpc);
	}
	if (found_spot != 1) {
		printf("cannot find signal %d   time: %u\n",sig,ctx->trace.global_time);
		assert(found_spot == 1);
	}
}

void rep_process_signal(struct context *ctx, bool validate)
{
	struct trace* trace = &(ctx->trace);
	int tid = ctx->child_tid;
	int sig = -trace->stop_reason;

	/* if the there is still a signal pending here, two signals in a row must be delivered?\n */
	assert(ctx->child_sig == 0);

	debug("%d: handling signal %d -- time: %d",tid,sig,trace->thread_time);

	switch (sig) {

	/* set the eax and edx register to the recorded values */
	case -SIG_SEGV_RDTSC:
	{
		struct user_regs_struct regs;
		int size;

		/* goto the event */
		goto_next_event(ctx);

		rep_child_buffer0(ctx); /* Set the wrapper record buffer size to 0 (if needed) */

		/* ake sure we are there */
		assert(WSTOPSIG(ctx->status) == SIGSEGV);

		char* inst = get_inst(tid, 0, &size);
		assert(strncmp(inst,"rdtsc",5) == 0);
		read_child_registers(tid, &regs);
		regs.eax = trace->recorded_regs.eax;
		regs.edx = trace->recorded_regs.edx;
		regs.eip += size;
		write_child_registers(tid, &regs);
		sys_free((void**) &inst);

		if (validate == TRUE)
			compare_register_files("rdtsc now", &regs, "rec", &ctx->trace.recorded_regs, 1, 1);

		/* this signal should not be recognized by the application */
		ctx->child_sig = 0;
		break;
	}


	{
		ctx->child_sig = 0;
		rep_child_buffer0(ctx); /* Set the wrapper record buffer size to 0 (if needed) */
		break;
	}

	case -USR_SCHED:
	{
		assert(trace->insts > 0);

		/* if the current architecture over-counts the event in question,
		 * subtract the overcount here */
 		// the seccomp syscalls do not reset the HPC
		assert(ctx->hpc->rbc.fd);
		uint64_t rbc_now = read_rbc(ctx->hpc);
		/* There's no need to set the rbc timer if we are already near the required rcb */
		while (rbc_now < trace->rbc - SKID_SIZE) {
			ctx->trace.rbc -= rbc_now;
			reset_hpc(ctx, trace->rbc - SKID_SIZE);
			goto_next_event(ctx);
			rbc_now = read_rbc(ctx->hpc);
			ctx->child_sig = 0;
		}
		assert(rbc_now >= trace->rbc - SKID_SIZE);
		/* make sure that the signal came from hpc */
		if (fcntl(ctx->hpc->rbc.fd, F_GETOWN) == ctx->child_tid) {
			/* this signal should not be recognized by the application */
			ctx->child_sig = 0;
			//stop_rbc(ctx);
			compensate_rbc_count(ctx, sig);
			rep_child_buffer0(ctx); /* Set the wrapper record buffer size to 0 (if needed) */
			stop_hpc(ctx);
		} else {
			fprintf(stderr, "internal error: next event should be: %d but it is: %d -- bailing out\n", -USR_SCHED, ctx->event);
			sys_exit();
		}

		break;
	}

	case SIGTERM:
	case SIGALRM:
	case SIGPIPE: // TODO
	case SIGWINCH:
	case SIGIO:
	case SIGCHLD:
	case 33: /* SIGRTMIN + 1 */
	case 62: /* SIGRTMAX - 1 */
	{

		if (trace->rbc == 0) { // synchronous signal (signal received in a system call)
			ctx->replay_sig = sig;
		} else {
			// setup and start replay counters
			// the seccomp syscalls do not reset the HPC
			assert(ctx->hpc->rbc.fd);
			ctx->trace.rbc -= read_rbc(ctx->hpc);
			reset_hpc(ctx, trace->rbc - SKID_SIZE);

			// single-step if the number of instructions to the next event is "small"
			if (trace->rbc <= 10000) {
				//stop_rbc(ctx);
				compensate_rbc_count(ctx, sig);
				stop_hpc(ctx);
			} else {
				log_info("large count");
				sys_ptrace_syscall(tid);
				sys_waitpid(tid, &ctx->status);
				// make sure we ere interrupted by ptrace
				assert(WSTOPSIG(ctx->status) == SIGIO);
				/* reset the penig sig, since it did not occur in the original execution */
				ctx->child_sig = 0;
				ctx->status = 0;

				//DO NOT FORGET TO STOP HPC!!!
				//stop_rbc(ctx);
				compensate_rbc_count(ctx, sig);
				stop_hpc(ctx);
			}
		}

		// we are now at the exact point in the child where the signal was recorded,
		// emulate it using the next trace line (records the state at sighandler entry)
		ctx = rep_sched_get_thread();
		if (set_child_data(ctx) > 0) { // only if we indeed entered a handler
			write_child_main_registers(ctx->child_tid,&trace->recorded_regs);
		}
		ctx->replay_sig = 0;

		break;
	}

	case SIGSEGV:
	{
		// synchronous signal (signal received in a system call)
		if (trace->rbc == 0 && trace->page_faults == 0) {
			ctx->replay_sig = sig;
		} else {
			sys_ptrace_syscall(ctx->child_tid);
			sys_waitpid(ctx->child_tid, &ctx->status);
			assert(WSTOPSIG(ctx->status) == SIGSEGV);

			struct user_regs_struct regs;
			read_child_registers(ctx->child_tid, &regs);
			assert(compare_register_files("segv now", &regs, "rec", &ctx->trace.recorded_regs, 1, 1) == 0);

			// deliver the signal
			//singlestep(ctx, SIGSEGV, 0x57f);
		}

		/* We are now at the exact point in the child where the signal was recorded
		 * emulate it using the next trace line (records the state at sighandler entry)
		 */
		rep_child_buffer0(ctx); /* Set the wrapper record buffer size to 0 (if needed) */
		ctx = rep_sched_get_thread();
		write_child_main_registers(ctx->child_tid,&trace->recorded_regs);
		set_child_data(ctx);
		ctx->replay_sig = 0;
		break;
	}

	case -SIG_SEGV_MMAP_READ:
	case -SIG_SEGV_MMAP_WRITE:
		fatal("mmap handling is currently disabled");
		break;

	default:
		fatal("unknown signal %d", sig);
		break;
	}
}
