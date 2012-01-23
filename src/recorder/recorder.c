#define _GNU_SOURCE

#include <assert.h>
#include <string.h>

#include <poll.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <linux/net.h>

#include "write_trace.h"
#include "rec_process_event.h"
#include "rec_sched.h"
#include "handle_signal.h"

#include "../share/hpc.h"
#include "../share/ipc.h"
#include "../share/sys.h"
#include "../share/util.h"

#define PTRACE_EVENT_NONE			0

/**
 * Single steps to the next event that must be recorded. This can either be a system call, or reading the time
 * stamp counter (for now)
 */
void goto_next_event_singlestep(struct context* context)
{
	pid_t tid = context->child_tid;

	while (1) {
		int inst_size;
		char* inst = get_inst(tid, 0, &inst_size);
		if ((strncmp(inst, "sysenter", 7) == 0) || (strncmp(inst, "int", 3) == 0)) {
			record_inst_done(context);
			free(inst);
			printf("breaking out\n");
			break;
		}
		record_inst(context, inst);
		free(inst);
		if (context->child_sig != 0) {
			//printf("pending sig: %d\n", context->pending_sig);
		}

		sys_ptrace_singlestep(tid, context->child_sig);
		sys_waitpid(tid, &(context->status));

		if (WSTOPSIG(context->status) == SIGSEGV) {
			break;
		}
	}

	assert(GET_PTRACE_EVENT(context->status)==0);
}

static void init_scratch_memory(struct context *ctx)
{
	/* initialize the scratchpad for blocking system calls */
	struct user_regs_struct orig_regs;

	read_child_registers(ctx->child_tid, &orig_regs);
	void *code = read_child_data(ctx, 4, read_child_eip(ctx->child_tid));

	/* set up the mmap system call */
	struct user_regs_struct mmap_call;
	memcpy(&mmap_call, &orig_regs, sizeof(struct user_regs_struct));

	const int scratch_size = 32 * sysconf(_SC_PAGE_SIZE);

	mmap_call.eax = SYS_mmap2;
	mmap_call.ebx = 0;
	mmap_call.ecx = scratch_size;
	mmap_call.edx = PROT_READ | PROT_WRITE | PROT_EXEC;
	mmap_call.esi = MAP_PRIVATE | MAP_ANONYMOUS;
	mmap_call.edi = -1;
	mmap_call.ebp = 0;
	write_child_registers(ctx->child_tid, &mmap_call);

	/* inject code that executes the additional system call */
	char syscall[] = { 0xcd, 0x80 };
	write_child_data(ctx, 2, mmap_call.eip, syscall);

	sys_ptrace_syscall(ctx->child_tid);
	sys_waitpid(ctx->child_tid, &ctx->status);

	sys_ptrace_syscall(ctx->child_tid);
	sys_waitpid(ctx->child_tid, &ctx->status);

	ctx->scratch_ptr = (void*) read_child_eax(ctx->child_tid);
	ctx->scratch_size = scratch_size;

	/* reset to the original state */
	write_child_registers(ctx->child_tid, &orig_regs);
	write_child_data(ctx, 2, mmap_call.eip, code);
	free(code);
}

static void cont_nonblock(struct context *ctx)
{
	sys_ptrace_syscall_sig(ctx->child_tid, ctx->child_sig);
	ctx->child_sig = 0;
}

static int wait_nonblock(struct context *ctx)
{
	int ret = sys_waitpid_nonblock(ctx->child_tid, &(ctx->status));

	if (ret) {
		assert(WIFEXITED(ctx->status) == 0);
		handle_signal(ctx);
		ctx->event = read_child_orig_eax(ctx->child_tid);
	}
	return ret;
}

static void cont_block(struct context *ctx)
{

	if (ctx->child_sig != 0) {
		printf("sending signal: %d\n",ctx->child_sig);
	}
	sys_ptrace(PTRACE_SYSCALL, ctx->child_tid, 0, (void*) ctx->child_sig);
	sys_waitpid(ctx->child_tid, &ctx->status);

	ctx->child_sig = signal_pending(ctx->status);
	ctx->event = read_child_orig_eax(ctx->child_tid);


	handle_signal(ctx);
}

static int allow_ctx_switch(struct context *ctx)
{
	int event = ctx->event;
	//printf("event: %d\n",event);
	/* int futex(int *uaddr, int op, int val, const struct timespec *timeout, int *uaddr2, int val3); */
	switch (event) {
	case SYS_futex:
	{
		struct user_regs_struct regs;
		read_child_registers(ctx->child_tid, &regs);

		int op = regs.ecx & FUTEX_CMD_MASK;

		if (op == FUTEX_WAIT || op == FUTEX_WAIT_BITSET || op == FUTEX_WAIT_PRIVATE || op == FUTEX_WAIT_REQUEUE_PI) {
			return 1;
		}

		if (op == FUTEX_WAKE_OP) {
			return 0;
		}

		return 0;
	}

	case SYS_socketcall:
	{
		int call = read_child_ebx(ctx->child_tid);
		struct user_regs_struct regs;
		read_child_registers(ctx->child_tid, &regs);
		printf("socket call: %d\n", call);
		if (call == SYS_SETSOCKOPT || call == SYS_GETSOCKNAME) {
			return 0;
		}

		/* ssize_t recv(int sockfd, void *buf, size_t len, int flags) */
		if (call == SYS_RECV) {
			uintptr_t *buf = read_child_data(ctx, sizeof(void*), regs.ecx + 4);
			size_t *len = read_child_data(ctx, sizeof(void*), regs.ecx + 8);
			printf("fucking len: %d\n", *len);
			assert(*len <= ctx->scratch_size);
			ctx->recorded_scratch_ptr = *buf;
			ctx->recorded_scratch_size = *len;
			write_child_data(ctx, sizeof(void*), regs.ecx + 4, &(ctx->scratch_ptr));

			sys_free((void**) &buf);
			sys_free((void**) &len);
			return 1;

			/* int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen); */
		} else if (call == SYS_ACCEPT) {
			//TODO: implement accept
			return 1;
		}

		return 1;
	}

	case SYS__newselect:
	{
		return 1;
	}

	/* ssize_t read(int fd, void *buf, size_t count); */
	case SYS_read:
	{
		struct user_regs_struct regs;
		read_child_registers(ctx->child_tid, &regs);
		assert(regs.edx <= ctx->scratch_size);

		ctx->recorded_scratch_ptr = regs.ecx;
		ctx->recorded_scratch_size = regs.edx;

		regs.ecx = ctx->scratch_ptr;
		write_child_registers(ctx->child_tid, &regs);
		return 1;
	}

	case SYS_write:
	{
		return 1;
	}

	/* this is a hack */
	case SYS_waitpid:
	case SYS_wait4:
	return 1;

	/* int poll(struct pollfd *fds, nfds_t nfds, int timeout) */
	case SYS_poll:
	{
		struct user_regs_struct regs;
		read_child_registers(ctx->child_tid, &regs);
		ctx->recorded_scratch_size = sizeof(struct pollfd) * regs.ecx;
		ctx->recorded_scratch_ptr = (void*) regs.ebx;
		assert(ctx->recorded_scratch_size <= ctx->scratch_size);

		/* copy the data */
		void *data = read_child_data(ctx, ctx->recorded_scratch_size, ctx->recorded_scratch_ptr);
		write_child_data(ctx, ctx->recorded_scratch_size, ctx->scratch_ptr, data);
		sys_free((void**) &data);

		regs.ebx = (long int) ctx->scratch_ptr;
		write_child_registers(ctx->child_tid, &regs);

		return 1;
	}

	/* int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout); */
	case SYS_epoll_wait:
	{
		struct user_regs_struct regs;
		read_child_registers(ctx->child_tid, &regs);
		ctx->recorded_scratch_size = sizeof(struct epoll_event) * regs.edx;
		ctx->recorded_scratch_ptr = regs.ecx;
		assert(ctx->recorded_scratch_size <= ctx->scratch_size);
		regs.ecx = (long int) ctx->scratch_ptr;
		write_child_registers(ctx->child_tid, &regs);
		return 1;
	}

	case SYS_epoll_pwait:
	{
		assert(1==0);
		return 1;
	}

	} /* end switch */

	return 0;
}

uintptr_t progress;

static void handle_ptrace_event(struct context **ctx_ptr)
{
	/* handle events */
	int event = GET_PTRACE_EVENT((*ctx_ptr)->status);
	printf("ptrace event: %d\n", event);
	switch (event) {

	case PTRACE_EVENT_NONE:
	{
		break;
	}

	case PTRACE_EVENT_VFORK_DONE:
	{


		rec_process_syscall(*ctx_ptr);
		record_event((*ctx_ptr), 1);
		(*ctx_ptr)->exec_state = EXEC_STATE_START;
		(*ctx_ptr)->allow_ctx_switch = 1;
		/* issue an additional continue, since the process was stopped by the additional ptrace event */
		cont_block(*ctx_ptr);
		break;
	}

	case PTRACE_EVENT_CLONE:
	case PTRACE_EVENT_FORK:
	case PTRACE_EVENT_VFORK:
	{
		/* get new tid, register at the scheduler and setup HPC */
		int new_tid = sys_ptrace_getmsg((*ctx_ptr)->child_tid);

		/* ensure that clone was successful */
		assert(read_child_eax((*ctx_ptr)->child_tid) != -1);

		/* wait until the new thread is ready */
		sys_waitpid(new_tid, &((*ctx_ptr)->status));
		rec_sched_register_thread((*ctx_ptr)->child_tid, new_tid);

		/* execute an additional ptrace_sysc((0xFF0000 & status) >> 16), since we setup trace like that.
		 * If the event is vfork we must no execute the cont_block, since the parent sleeps until the
		 * child has finished */
		if (event == PTRACE_EVENT_VFORK) {
			(*ctx_ptr)->exec_state = EXEC_STATE_IN_SYSCALL;
			(*ctx_ptr)->allow_ctx_switch = 1;
			record_event((*ctx_ptr), 3);
			cont_nonblock((*ctx_ptr));
		} else {
			cont_block((*ctx_ptr));
		}
		break;
	}

	case PTRACE_EVENT_EXEC:
	{
		cont_block((*ctx_ptr));
		init_scratch_memory(*ctx_ptr);
		assert(signal_pending((*ctx_ptr)->status) == 0);
		break;
	}

	case PTRACE_EVENT_EXIT:
	{
		(*ctx_ptr)->event = USR_EXIT;
		record_event((*ctx_ptr), 1);
		rec_sched_deregister_thread(ctx_ptr);
		break;
	}

	default:
	{
		fprintf(stderr, "Unknown ptrace event: %x -- baling out\n", event);
		sys_exit();
		break;
	}

	} /* end switch */
}

void start_recording()
{
	struct context *ctx = NULL;

	/* record the initial status of the register file */
	ctx = get_active_thread(ctx);
	ctx->event = -1000;
	record_event(ctx, 0);
	init_scratch_memory(ctx);

	while (rec_sched_get_num_threads() > 0) {
		/* get a thread that is ready to be executed */
		ctx = get_active_thread(ctx);

		if (ctx->scratch_ptr == NULL) {
			init_scratch_memory(ctx);
		}
		/* the child process will either be interrupted by: (1) a signal, or (2) at
		 * the entry of the system call */

		/* simple state machine to guarantee process in the application */
		switch (ctx->exec_state) {

		case EXEC_STATE_START:
		{
			//goto_next_event_singlestep(context);

			/* print some kind of progress */
			if (progress++ % 10000 == 0) {
				printf(".");
				fflush(stdout);
			}

			/* we need to issue a blocking continue here to serialize program execution */

			printf("1: tid: %d   event: %d\n", ctx->child_tid, ctx->event);
			cont_block(ctx);
			/* we must disallow the context switch here! */
			ctx->allow_ctx_switch = 0;
			assert(GET_PTRACE_EVENT(ctx->status) == 0);

			if (GET_PTRACE_EVENT(ctx->status)) {
				assert(1==0);
			}

			/* state might be overwritten if a signal occurs */
			if (ctx->event == SIG_SEGV_RDTSC || ctx->event == USR_SCHED) {
				ctx->allow_ctx_switch = 1;

				/* Implements signal handling
				 *
				 * IMPORTANT: context switches must be disallowed to ensure that the correct
				 * process/threads gets the signal delivered. We do not change the state here since
				 * we have not arrived at a new system call.
				 */
			} else if (ctx->child_sig) {

				/* These system calls never return; we remain in the same execution state */
			} else if (ctx->event == SYS_sigreturn || ctx->event == SYS_rt_sigreturn) {
				/* we record the sigreturn event here, since we have to do another ptrace_cont to
				 * fullt process the sigreturn system call.
				 */
				int orig_event = ctx->event;
				record_event(ctx, 0);
				/* do another step */
				cont_block(ctx);

				assert(ctx->child_sig == 0);
				/* the next event is -1 -- how knows why?*/
				assert(ctx->event == -1);
				ctx->event = orig_event;
				record_event(ctx, 0);
				ctx->allow_ctx_switch = 1;

				/* here we can continue normally */
				break;

			} else if (ctx->event > 0) {
				ctx->exec_state = EXEC_STATE_ENTRY_SYSCALL;

				/* this is a wired state -- no idea why it works */
			} else if (ctx->event == SYS_restart_syscall) {

				assert(1==0);

				/* we sould never come here */
			} else {
				assert(1==0);
			}

			record_event(ctx, 0);
			break;
		}

		case EXEC_STATE_ENTRY_SYSCALL:
		{
			/* continue and execute the system call */
			ctx->allow_ctx_switch = allow_ctx_switch(ctx);
			cont_nonblock(ctx);
			ctx->exec_state = EXEC_STATE_IN_SYSCALL;
			break;
		}

		case EXEC_STATE_IN_SYSCALL:
		{

			//printf("now we are at: %d  status: %x\n", ctx->event, ctx->status);
			int ret = wait_nonblock(ctx);
			if (ret) {
				assert(signal_pending(ctx->status) == 0);

				/* we received a signal while in the system call and send it right away*/
				/* we have already sent the signal and process sigreturn */
				if (ctx->event == SYS_sigreturn) {
					assert(1==0);
				}

				handle_ptrace_event(&ctx);

				if ((ctx != NULL) && (ctx->event != SYS_vfork)) {
					int sig = signal_pending(ctx->status);
					if (sig) {
						ctx->child_sig = sig;
					}
					rec_process_syscall(ctx);
					record_event(ctx, 1);
					ctx->exec_state = EXEC_STATE_START;
					ctx->allow_ctx_switch = 1;
				}
			}
			break;
		}

		default:
		errx(1, "Unknown execution state: %x -- bailing out\n", ctx->exec_state);
			break;
		}
	} /* while loop */
}
