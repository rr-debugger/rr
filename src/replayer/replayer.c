/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#define _GNU_SOURCE

#include "replayer.h"

#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/poll.h>
#include <sys/ptrace.h>
#include <asm/ptrace-abi.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/user.h>
#include <unistd.h>

#include "dbg_gdb.h"
#include "rep_sched.h"
#include "rep_process_event.h"
#include "rep_process_signal.h"

#include "../share/dbg.h"
#include "../share/hpc.h"
#include "../share/trace.h"
#include "../share/ipc.h"
#include "../share/sys.h"
#include "../share/util.h"
#include "../share/wrap_syscalls.h"

#include <perfmon/pfmlib_perf_event.h>

#define SAMPLE_SIZE 		10
#define NUM_SAMPLE_PAGES 	1

static const struct dbg_request continue_all_tasks = {
	.type = DREQ_CONTINUE,
	.target = { .pid = -1, .tid = -1 },
	.params = { {0} }
};

static const struct flags* rr_flags;

/* Nonzero after the first exec() has been observed during replay.
 * After this point, the first recorded binary image has been exec()d
 * over the initial rr image. */
static bool validate = FALSE;

/**
 * Every time a non-wrapped event happens, the hpc is reset. when an
 * event that requires hpc occures, we read the hpc at that point and
 * reset the hpc interval to the required rbc minus the current hpc.
 * all this happens since the wrapped event do not reset the hpc,
 * therefore the previous techniques of starting the hpc only the at
 * the previous event to the one that requires it, doesn't work, since
 * the previous event may be a wrapped syscall
 */
static void rep_reset_hpc(struct context * ctx) {
	if (!ctx || ctx->trace.stop_reason == USR_FLUSH)
		return;
	reset_hpc(ctx,0);
}

static void check_initial_register_file()
{
	rep_sched_get_thread();
}

static void replay_init_scratch_memory(struct context *ctx,
				       struct mmapped_file *file)
{
    /* initialize the scratchpad as the recorder did, but
     * make it PROT_NONE. The idea is just to reserve the
     * address space so the replayed process address map
     * looks like the recorded process, if it were to be
     * probed by madvise or some other means. But we make
     * it PROT_NONE so that rogue reads/writes to the
     * scratch memory are caught.
     */

    /* set up the mmap system call */
    struct user_regs_struct orig_regs;
    read_child_registers(ctx->child_tid, &orig_regs);

    struct user_regs_struct mmap_call = orig_regs;

    mmap_call.eax = SYS_mmap2;
    mmap_call.ebx = (uintptr_t)file->start;
    mmap_call.ecx = file->end - file->start;
    mmap_call.edx = PROT_NONE;
    mmap_call.esi = MAP_PRIVATE | MAP_ANONYMOUS;
    mmap_call.edi = -1;
    mmap_call.ebp = 0;

    inject_and_execute_syscall(ctx,&mmap_call);

    write_child_registers(ctx->child_tid,&orig_regs);
}

/**
 * Return the value of |reg| in |regs|, or set |*defined = 0| and
 * return an undefined value if |reg| isn't found.
 */
static long get_reg(const struct user_regs_struct* regs, dbg_register reg,
		    int* defined)
{
	*defined = 1;
	switch (reg) {
	case DREG_EAX: return regs->eax;
	case DREG_ECX: return regs->ecx;
	case DREG_EDX: return regs->edx;
	case DREG_EBX: return regs->ebx;
	case DREG_ESP: return regs->esp;
	case DREG_EBP: return regs->ebp;
	case DREG_ESI: return regs->esi;
	case DREG_EDI: return regs->edi;
	case DREG_EIP: return regs->eip;
	case DREG_EFLAGS: return regs->eflags;
	case DREG_CS: return regs->xcs;
	case DREG_SS: return regs->xss;
	case DREG_DS: return regs->xds;
	case DREG_ES: return regs->xes;
	case DREG_FS: return regs->xfs;
	case DREG_GS: return regs->xgs;
	case DREG_ORIG_EAX: return regs->orig_eax;
	default:
		*defined = 0;
		return 0;
	}
}

static dbg_threadid_t get_threadid(struct context* ctx)
{
	dbg_threadid_t thread = { .pid = -1, .tid = ctx->rec_tid };
	return thread;
}

static byte* read_mem(struct context* ctx, void* addr, size_t len)
{
	/* XXX will gdb ever make request for unreadable memory?  If
	 * so, we need to use read_child_data_checked() here. */
	return read_child_data_tid(ctx->child_tid, len, addr);
}

/* Reply to debugger requests until the debugger asks us to resume
 * execution. */
static struct dbg_request process_debugger_requests(struct dbg_context* dbg,
						    struct context* ctx)
{
	if (!dbg) {
		return continue_all_tasks;
	}
	while (1) {
		struct dbg_request req = dbg_get_request(dbg);
		if (dbg_is_resume_request(&req)) {
			return req;
		}

		switch (req.type) {
		case DREQ_GET_CURRENT_THREAD: {
			dbg_reply_get_current_thread(dbg, get_threadid(ctx));
			continue;
		}
		case DREQ_GET_IS_THREAD_ALIVE:
			dbg_reply_get_is_thread_alive(
				dbg, !!rep_sched_lookup_thread(req.target.tid));
			continue;
		case DREQ_GET_MEM: {
			byte* mem = read_mem(ctx, req.params.mem.addr,
					     req.params.mem.len);
			dbg_reply_get_mem(dbg, mem);
			sys_free((void**)&mem);
			continue;
		}
		case DREQ_GET_OFFSETS:
			/* TODO */
			dbg_reply_get_offsets(dbg);
			continue;
		case DREQ_GET_REGS: {
			struct user_regs_struct regs;
			struct dbg_regfile file;
			int i;
			dbg_regvalue_t* val;

			read_child_registers(ctx->child_tid, &regs);
			memset(&file, 0, sizeof(file));
			for (i = DREG_EAX; i < DREG_NUM_USER_REGS; ++i) {
				val = &file.regs[i];
				val->value = get_reg(&regs, i, &val->defined);
			}
			val = &file.regs[DREG_ORIG_EAX];
			val->value = get_reg(&regs, DREG_ORIG_EAX,
					     &val->defined);

			dbg_reply_get_regs(dbg, &file);
			continue;
		}
		case DREQ_GET_REG: {
			struct user_regs_struct regs;
			dbg_regvalue_t val;

			read_child_registers(ctx->child_tid, &regs);
			val.value = get_reg(&regs, req.params.reg,
					    &val.defined);
			dbg_reply_get_reg(dbg, val);
			continue;
		}
		case DREQ_GET_STOP_REASON:
			/* TODO */
			dbg_reply_get_stop_reason(dbg);
			continue;
		case DREQ_GET_THREAD_LIST: {
			/* TODO */
			dbg_threadid_t list = get_threadid(ctx);
			dbg_reply_get_thread_list(dbg, &list, 1);
			continue;
		}
		case DREQ_INTERRUPT:
			/* Tell the debugger we stopped and
			 * await further instructions. */
			dbg_notify_stop(dbg, get_threadid(ctx), 0);
			continue;
		default:
			fatal("Unknown debugger request %d", req.type);
		}
	}
}

static void replay_one_trace_step(struct dbg_context* dbg, struct context* ctx)
{
	struct dbg_request req;

	/* Advance the trace until we've exec()'d the tracee before
	 * processing debugger requests.  Otherwise the debugger host
	 * will be confused about the initial executable image,
	 * rr's. */
	if (validate) {
		req = process_debugger_requests(dbg, ctx);
		assert(dbg_is_resume_request(&req));
	}

	/* print some kind of progress */
	if (ctx->trace.global_time % 10000 == 0) {
		fprintf(stderr, "time: %u\n",ctx->trace.global_time);
	}

	if (ctx->child_sig != 0) {
		//printf("child_sig: %d\n",ctx->child_sig);
		assert(ctx->trace.stop_reason == -ctx->child_sig);
		ctx->child_sig = 0;
	}

	if (ctx->trace.stop_reason == USR_INIT_SCRATCH_MEM) {
		/* for checksumming: make a note that this area is
		 * scratch and need not be validated. */
		struct mmapped_file file;
		read_next_mmapped_file_stats(&file);
		replay_init_scratch_memory(ctx, &file);
		add_scratch((void*)ctx->trace.recorded_regs.eax,
			    file.end - file.start);
	} else if (ctx->trace.stop_reason == USR_EXIT) {
		rep_sched_deregister_thread(&ctx);
	} else if(ctx->trace.stop_reason > 0) {
		/* stop reason is a system call - can be done with ptrace */
		if (ctx->trace.state == STATE_SYSCALL_EXIT) {
			if (ctx->trace.stop_reason == SYS_execve) {
				validate = TRUE;
			}
			/* when a syscall exits with either of these
			 * errors, it will be restarted by the kernel
			 * with a restart syscall. The child process
			 * is oblivious to this, so in the replay we
			 * need to jump directly to the exit from the
			 * restart_syscall */
			if ((ctx->trace.recorded_regs.eax == ERESTART_RESTARTBLOCK
			     || ctx->trace.recorded_regs.eax == ERESTARTNOINTR) ) {
				return;
			}
		}

		/* proceed to the next event */
		rep_process_syscall(ctx, ctx->trace.stop_reason,
				    rr_flags->redirect);
	} else if (ctx->trace.stop_reason == SYS_restart_syscall) {
		/* the restarted syscall will be replayed by the next
		 * entry which is an exit entry for the original
		 * syscall being restarted - do nothing here. */
		return;
	} else if (ctx->trace.stop_reason == USR_FLUSH) {
		rep_process_flush(ctx);
	} else {
		/* stop reason is a signal - use HPC */
		rep_process_signal(ctx, validate);
	}

	rep_reset_hpc(ctx);

	/* dump memory as user requested */
	if (ctx
	    && (rr_flags->dump_on == ctx->trace.stop_reason
		|| rr_flags->dump_on == DUMP_ON_ALL
		|| rr_flags->dump_at == ctx->trace.global_time)) {
		char pid_str[PATH_MAX];
		snprintf(pid_str, sizeof(pid_str) - 1, "%s/%d_%d_rep",
			 get_trace_path(),
			 ctx->child_tid, ctx->trace.global_time);
		print_process_memory(ctx, pid_str);
	}

	/* check memory checksum */
	if (ctx && validate
	    && ((rr_flags->checksum == CHECKSUM_ALL)
		|| (rr_flags->checksum == CHECKSUM_SYSCALL
		    && ctx->trace.state == STATE_SYSCALL_EXIT)
		|| (rr_flags->checksum <= ctx->trace.global_time))) {
		validate_process_memory(ctx);
	}
}

void replay(struct flags flags)
{
	struct dbg_context* dbg = NULL;

	rr_flags = &flags;

	if (!rr_flags->autopilot) {
		dbg = dbg_await_client_connection("127.0.0.1",
						  rr_flags->dbgport);
	}

	check_initial_register_file();

	while (rep_sched_get_num_threads()) {
		replay_one_trace_step(dbg, rep_sched_get_thread());
	}

	log_info("Replayer successfully finished.");
	fflush(stdout);

	dbg_destroy_context(&dbg);
}
