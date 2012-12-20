#define _GNU_SOURCE

#include <assert.h>
#include <string.h>

#include <poll.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
 #include <sys/resource.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <linux/net.h>

#include "rec_process_event.h"
#include "rec_sched.h"
#include "handle_signal.h"

#include "../share/dbg.h"
#include "../share/hpc.h"
#include "../share/ipc.h"
#include "../share/trace.h"
#include "../share/sys.h"
#include "../share/util.h"
#include "../share/wrap_syscalls.h"

#define PTRACE_EVENT_NONE			0
static struct flags rr_flags_ = { 0 };
static bool filter_on_ = FALSE;

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
			debug("pending sig: %d\n", context->child_sig);
		}

		sys_ptrace_singlestep(tid, context->child_sig);
		context->child_sig = 0;
		sys_waitpid(tid, &(context->status));

		if (WSTOPSIG(context->status) == SIGSEGV) {
			break;
		}
	}

	assert(GET_PTRACE_EVENT(context->status)==0);
}

static void rec_init_scratch_memory(struct context *ctx)
{
	/* initialize the scratchpad for blocking system calls */

	/* set up the mmap system call */
	struct user_regs_struct mmap_call;
	read_child_registers(ctx->child_tid, &mmap_call);

	const int scratch_size = 512 * sysconf(_SC_PAGE_SIZE);

	mmap_call.eax = SYS_mmap2;
	mmap_call.ebx = 0;
	mmap_call.ecx = scratch_size;
	mmap_call.edx = PROT_READ | PROT_WRITE | PROT_EXEC;
	mmap_call.esi = MAP_PRIVATE | MAP_ANONYMOUS;
	mmap_call.edi = -1;
	mmap_call.ebp = 0;

	ctx->scratch_ptr = (void*)inject_and_execute_syscall(ctx,&mmap_call);
	ctx->scratch_size = scratch_size;

	// record this mmap for the replay
	struct user_regs_struct orig_regs;
	read_child_registers(ctx->child_tid,&orig_regs);
	int eax = orig_regs.eax;
	orig_regs.eax = ctx->scratch_ptr;
	write_child_registers(ctx->child_tid,&orig_regs);
	struct mmapped_file file = {0};
	file.time = get_global_time();
	file.tid = ctx->child_tid;
	file.start = ctx->scratch_ptr;
	file.end = ctx->scratch_ptr + scratch_size;
	sprintf(file.filename,"scratch for thread %d",ctx->child_tid);
	record_mmapped_file_stats(&file);
	int event = ctx->event;
	ctx->event = USR_INIT_SCRATCH_MEM;
	record_event(ctx,STATE_SYSCALL_EXIT);
	ctx->event = event;
	orig_regs.eax = eax;
	write_child_registers(ctx->child_tid,&orig_regs);

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

static int wait_block_timeout(struct context *ctx, int timeout_us)
{
	int ret = sys_waitpid_timeout(ctx->child_tid, &(ctx->status), timeout_us);

	if (ret) {
		assert(WIFEXITED(ctx->status) == 0);
		handle_signal(ctx);
		ctx->event = read_child_orig_eax(ctx->child_tid);
	}
	return ret;
}

/**
 * Continue the child until it gets a signal or a ptrace event
 */
static void cont_block(struct context *ctx)
{
	sys_ptrace(PTRACE_CONT, ctx->child_tid, 0, (void*) ctx->child_sig);
	sys_waitpid(ctx->child_tid, &ctx->status);
	ctx->child_sig = signal_pending(ctx->status);
	read_child_registers(ctx->child_tid, &(ctx->child_regs));
	ctx->event = ctx->child_regs.orig_eax;
	handle_signal(ctx);
}

/**
 * Continue the child until it gets a signal, a syscall or a ptrace event
 */
static void cont_syscall_block(struct context *ctx)
{
	sys_ptrace(PTRACE_SYSCALL, ctx->child_tid, 0, (void*) ctx->child_sig);
	sys_waitpid(ctx->child_tid, &ctx->status);
	ctx->child_sig = signal_pending(ctx->status);
	read_child_registers(ctx->child_tid, &(ctx->child_regs));
	ctx->event = ctx->child_regs.orig_eax;
	handle_signal(ctx);
}

static int allow_ctx_switch(struct context *ctx, int event)
{
	/**
	 * If we are called again due to a restart_syscall, we musn't redirect to scratch again
	 * as we will lose the original addresses values.
	 */
	bool restart = (event == SYS_restart_syscall);
	if (restart) {
		event = ctx->last_syscall;
	}

	switch (event) {

	case USR_SCHED:
	{
		return 1;
	}

	/* int futex(int *uaddr, int op, int val, const struct timespec *timeout, int *uaddr2, int val3); */
	case SYS_futex:
	{

		switch (ctx->child_regs.ecx & FUTEX_CMD_MASK) {
		case FUTEX_WAIT:
		case FUTEX_WAIT_BITSET:
		case FUTEX_WAIT_PRIVATE:
		case FUTEX_WAIT_REQUEUE_PI:
			return 1;
		default:
			return 0;
		}
		break;
	}

	case SYS_socketcall:
	{
		switch (ctx->child_regs.ebx) {
		/* ssize_t recv(int sockfd, void *buf, size_t len, int flags) :=
		 * int socketcall(int call, unsigned long *args) {
		 * 		long a[6];
		 * 		copy_from_user(a,args);
		 *  	sys_recv(a0, (void __user *)a1, a[2], a[3]);
		 *  }
		 *
		 *  (fropm http://lxr.linux.no/#linux+v3.6.3/net/socket.c#L2354)
		 */
		case SYS_RECV:
		{
			if (!restart) {
				struct user_regs_struct regs;
				read_child_registers(ctx->child_tid, &regs);
				/* We need to point to scratch memory only if the eip is not in the wrapper lib. */				
				if (!WRAP_SYSCALLS_CALLSITE_IN_WRAPPER(regs.eip,ctx)) {
					size_t num_args = 4;
					// reading syscall args
					unsigned long * args = read_child_data(ctx, num_args * sizeof(long),regs.ecx);
					// save buffer address (args[1]) and size
					ctx->recorded_scratch_ptr_1 = (void*)args[1];
					ctx->recorded_scratch_size = args[2];
					// setting buffer address to scratch memory +  sizeof the args
					args[1] = (long)(ctx->scratch_ptr + (num_args * sizeof(long)));
					// put args on scratch memory (since as we changed it)
					write_child_data(ctx, num_args * sizeof(long), ctx->scratch_ptr, args);
					// point ecx to args
					ctx->recorded_scratch_ptr_0 = regs.ecx;
					regs.ecx = (long)ctx->scratch_ptr;
					write_child_registers(ctx->child_tid,&regs);
					// cleanup
					sys_free((void**)&args);
				}
			}
			return 1;
		}
		/* int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen); =
		 * sys_accept4(a0, (struct sockaddr __user *)a1,(int __user *)a[2], 0);
		 * */
		case SYS_ACCEPT:
		{
			if (!restart) {
				struct user_regs_struct regs;
				read_child_registers(ctx->child_tid, &regs);
				/* We need to point to scratch memory only if the eip is not in the wrapper lib. */
				if (!WRAP_SYSCALLS_CALLSITE_IN_WRAPPER(regs.eip,ctx)) {
					size_t num_args = 3;
					// reading syscall args
					unsigned long * args = read_child_data(ctx, num_args * sizeof(long),regs.ecx);
					// setting addr to scratch memory +  sizeof the args
					ctx->recorded_scratch_ptr_1 = args[1];
					args[1] = (long)(ctx->scratch_ptr + (num_args * sizeof(long)));
					// setting addrlen to addr + addrlen
					socklen_t *addrlen = read_child_data(ctx,sizeof(socklen_t *),args[2]);
					ctx->recorded_scratch_size = *addrlen;
					args[2] = (long)((void*)args[1] + *addrlen);
					// put args on scratch memory (since we changed it)
					write_child_data(ctx, num_args * sizeof(long), ctx->scratch_ptr, args);
					// point ecx to args
					ctx->recorded_scratch_ptr_0 = regs.ecx;
					regs.ecx = (long)ctx->scratch_ptr;
					write_child_registers(ctx->child_tid,&regs);
					// cleanup
					sys_free((void**)&addrlen);
					sys_free((void**)&args);
				}
			}
			return 1;
		}
		default:
			return 0;
		}
		break;
	}

	case SYS__newselect:
	{
		return 1;
	}

	/* ssize_t read(int fd, void *buf, size_t count); */
	case SYS_read:
	{
		if (!restart) {
			struct user_regs_struct regs;
			read_child_registers(ctx->child_tid, &regs);
			/* We need to point to scratch memory only if the eip is not in the wrapper lib. */
			if (!WRAP_SYSCALLS_CALLSITE_IN_WRAPPER(regs.eip,ctx)) {
				int size = regs.edx;
				if (size < 0 || size > ctx->scratch_size) {
					log_info("Syscall %d called with bad size %d  (scratch size = %d)", size, ctx->scratch_size);
					ctx->recorded_scratch_size = -1;
					return 0;
				}
				ctx->recorded_scratch_ptr_0 = regs.ecx;
				ctx->recorded_scratch_size = size;
				regs.ecx = ctx->scratch_ptr;
				write_child_registers(ctx->child_tid, &regs);
			}
		}
		return 1;
	}

	/* Generally, it is faster to wait for a SYS_write to return
	 * than to do a context switch. However, after waiting for a
	 * certain amount of time (see config.h), a context switch is
	 * performed.
	 */
	case SYS_write:
	{
		return 0;
	}

	/* pid_t waitpid(pid_t pid, int *status, int options); */
	/* pid_t wait4(pid_t pid, int *status, int options, struct rusage *rusage); */
	case SYS_waitpid:
	case SYS_wait4:
	{
		if (!restart) {
			struct user_regs_struct regs;
			read_child_registers(ctx->child_tid, &regs);
			/* We need to point to scratch memory only if the eip is not in the wrapper lib. */
			if (!WRAP_SYSCALLS_CALLSITE_IN_WRAPPER(regs.eip,ctx)) {
				bool registers_changed = FALSE;
				void * ptr = ctx->scratch_ptr;
				ctx->recorded_scratch_size = 0;
				if (regs.ecx) { /* if status is non-null, redirect it to scratch */
					ctx->recorded_scratch_ptr_0 = (void*)regs.ecx;
					ctx->recorded_scratch_size += sizeof(int);
					regs.ecx = (int)ptr;
					registers_changed = TRUE;
					ptr += sizeof(int);
				} else {
					ctx->recorded_scratch_ptr_0 = (void*)-1;
				}
				if (event == SYS_wait4 && regs.esi) { /* if rusage is non-null, redirect it to scratch */
					ctx->recorded_scratch_ptr_1 = (void*)regs.esi;
					ctx->recorded_scratch_size += sizeof(struct rusage);
					regs.esi = (int)ptr;
					registers_changed = TRUE;
					ptr += sizeof(struct rusage);
				} else {
					ctx->recorded_scratch_ptr_1 = (void*)-1;
				}
				if (registers_changed) {
					write_child_registers(ctx->child_tid, &regs);
				}
			}
		}
		return 1;
	}

	/* int poll(struct pollfd *fds, nfds_t nfds, int timeout) */
	case SYS_poll:
	{
		if (!restart) {
			struct user_regs_struct regs;
			read_child_registers(ctx->child_tid, &regs);
			/* We need to point to scratch memory only if the eip is not in the wrapper lib. */
			if (!WRAP_SYSCALLS_CALLSITE_IN_WRAPPER(regs.eip,ctx)) {
				int size = sizeof(struct pollfd) * regs.ecx;
				if (size < 0 || size > ctx->scratch_size) {
					log_info("Syscall %d called with bad size %d  (scratch size = %d)", size, ctx->scratch_size);
					ctx->recorded_scratch_size = -1;
					return 0;
				}
				ctx->recorded_scratch_size = size;
				ctx->recorded_scratch_ptr_0 = (void*) regs.ebx;
				assert(ctx->recorded_scratch_size <= ctx->scratch_size);

				// copy the data
				struct pollfd *data = (struct pollfd *)read_child_data(ctx, ctx->recorded_scratch_size, ctx->recorded_scratch_ptr_0);
				write_child_data(ctx, ctx->recorded_scratch_size, ctx->scratch_ptr, data);
				sys_free((void**) &data);

				regs.ebx = (long int) ctx->scratch_ptr;
				write_child_registers(ctx->child_tid, &regs);
			}
		}
		return 1;
	}

	/* int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5); */
	// TODO: this may be a quick syscall, better not to allow context switching -- benchmarking needed
	case SYS_prctl:
	{
		if (!restart) {
			struct user_regs_struct regs;
			read_child_registers(ctx->child_tid, &regs);
			/* We need to point to scratch memory only if the eip is not in the wrapper lib. */
			if (!WRAP_SYSCALLS_CALLSITE_IN_WRAPPER(regs.eip,ctx)) {
				switch (regs.ebx)
				{
					case PR_GET_ENDIAN: 	/* Return the endian-ness of the calling process, in the location pointed to by (int *) arg2 */
					case PR_GET_FPEMU:  	/* Return floating-point emulation control bits, in the location pointed to by (int *) arg2. */
					case PR_GET_FPEXC:  	/* Return floating-point exception mode, in the location pointed to by (int *) arg2. */
					case PR_GET_PDEATHSIG:  /* Return the current value of the parent process death signal, in the location pointed to by (int *) arg2. */
					case PR_GET_TSC:		/* Return the state of the flag determining whether the timestamp counter can be read, in the location pointed to by (int *) arg2. */
					case PR_GET_UNALIGN:    /* Return unaligned access control bits, in the location pointed to by (int *) arg2. */
						ctx->recorded_scratch_size = sizeof(int);
						ctx->recorded_scratch_ptr_0 = (void*) regs.ecx;
						regs.ecx = ctx->scratch_ptr;
						write_child_registers(ctx->child_tid, &regs);
						break;
					case PR_GET_NAME:   /*  Return the process name for the calling process, in the buffer pointed to by (char *) arg2.
											The buffer should allow space for up to 16 bytes;
											The returned string will be null-terminated if it is shorter than that. */
						ctx->recorded_scratch_size = 16;
						ctx->recorded_scratch_ptr_0 = (void*) regs.ecx;
						regs.ecx = ctx->scratch_ptr;
						write_child_registers(ctx->child_tid, &regs);
						break;
					default:
						break;
				}
			}
		}
		return 1;
	}

	/* int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout); */
	case SYS_epoll_wait:
	{
		if (!restart) {
			struct user_regs_struct regs;
			read_child_registers(ctx->child_tid, &regs);
			/* We need to point to scratch memory only if the eip is not in the wrapper lib. */
			if (!WRAP_SYSCALLS_CALLSITE_IN_WRAPPER(regs.eip,ctx)) {
				int size = sizeof(struct epoll_event) * regs.edx;
				if (size < 0 || size > ctx->scratch_size) {
					log_info("Syscall %d called with bad size %d  (scratch size = %d)", size, ctx->scratch_size);
					ctx->recorded_scratch_size = -1;
					return 0;
				}
				ctx->recorded_scratch_size = size;
				ctx->recorded_scratch_ptr_0 = regs.ecx;
				regs.ecx = (long int) ctx->scratch_ptr;
				write_child_registers(ctx->child_tid, &regs);
			}
		}
		return 1;
	}

	case SYS_epoll_pwait:
	{
		assert(0);
		return 1;
	}

	/**************************************************************
	 * The system calls that come here allow a context switch for
	 * performance reasons
	 **************************************************************/
	/* int nanosleep(const struct timespec *req, struct timespec *rem); */
	case SYS_nanosleep:
	{
		if (!restart) {
			struct user_regs_struct regs;
			read_child_registers(ctx->child_tid, &regs);
			/* We need to point to scratch memory only if the eip is not in the wrapper lib. */
			if (!WRAP_SYSCALLS_CALLSITE_IN_WRAPPER(regs.eip,ctx)) {
				ctx->recorded_scratch_ptr_0 = (void*) regs.ecx;
				ctx->recorded_scratch_size = sizeof(struct timespec);
				regs.ecx = ctx->scratch_ptr;
				write_child_registers(ctx->child_tid, &regs);
			}
		}
		return 1;
	}

	case SYS_sched_yield:
	{
		return 1;
	}

	default:
		return 0;

	} /* end switch */

	return 0;
}

uintptr_t progress;

static void handle_ptrace_event(struct context **ctx_ptr)
{
	/* handle events */
	int event = GET_PTRACE_EVENT((*ctx_ptr)->status);
	debug("Recording syscall %d, ptrace event: %d, thread: %d", (*ctx_ptr)->event, event, (*ctx_ptr)->child_tid);
	switch (event) {

	case PTRACE_EVENT_NONE:
	{
		break;
	}

	case PTRACE_EVENT_VFORK_DONE:
	{
		rec_process_syscall(*ctx_ptr, (*ctx_ptr)->event, rr_flags_);
		record_event((*ctx_ptr), STATE_SYSCALL_EXIT);
		(*ctx_ptr)->exec_state = EXEC_STATE_START;
		(*ctx_ptr)->allow_ctx_switch = 1;
		/* issue an additional continue, since the process was stopped by the additional ptrace event */
		cont_syscall_block(*ctx_ptr);
		record_event((*ctx_ptr), STATE_SYSCALL_EXIT);
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
			record_event((*ctx_ptr), STATE_SYSCALL_ENTRY);
			cont_nonblock((*ctx_ptr));
		} else {
			cont_syscall_block((*ctx_ptr));
		}
		break;
	}

	case PTRACE_EVENT_EXEC:
	{
		record_event(*ctx_ptr, STATE_SYSCALL_ENTRY);
		cont_syscall_block(*ctx_ptr);
		rec_init_scratch_memory(*ctx_ptr);
		assert(signal_pending((*ctx_ptr)->status) == 0);
		break;
	}

	case PTRACE_EVENT_EXIT:
	{
		(*ctx_ptr)->event = USR_EXIT;
		record_event((*ctx_ptr), STATE_SYSCALL_EXIT);
		rec_sched_deregister_thread(ctx_ptr);
		/*
		 * This is a dirty workaround: If a thread issues the exit_group system call, it may happen
		 * that the thread that gets scheduled after this one is stopped, so rr will let it continue,
		 * but in fact it is "not  yet  fully  dead, but already refusing ptrace requests".
		 * TODO: track thread group of threads and handle this case properly by deregistering them
		 * directly
		 */
		usleep(100);
		break;
	}

	default:
	{
		log_err("Unknown ptrace event: %x -- baling out", event);
		sys_exit();
		break;
	}

	} /* end switch */
}

void start_recording(struct flags rr_flags)
{
	rr_flags_ = rr_flags;
	struct context *ctx = NULL;

	/* record the initial status of the register file */
	ctx = get_active_thread(ctx);
	ctx->event = -1000;
	record_event(ctx, STATE_SYSCALL_ENTRY);
	rec_init_scratch_memory(ctx);

	while (rec_sched_get_num_threads() > 0) {
		/* get a thread that is ready to be executed */
		ctx = get_active_thread(ctx);

		if (ctx->scratch_ptr == NULL) {
			rec_init_scratch_memory(ctx);
		}
		/* the child process will either be interrupted by: (1) a signal, or (2) at
		 * the entry of the system call */

		/* simple state machine to guarantee process in the application */
		switch (ctx->exec_state) {

		case EXEC_STATE_START:
		{

			/* print some kind of progress */
			if (progress++ % 10000 == 0) {
				fprintf(stderr,".");
				fflush(stdout);
			}

			/* we need to issue a blocking continue here to serialize program execution */

			/**
			 * We won't receive PTRACE_EVENT_SECCOMP events until the seccomp filter is installed
			 * by the wrap_syscall lib in the child, therefore we must record in the traditional way (with PTRACE_SYSCALL)
			 * until it is installed.
			 */
			if (filter_on_) {
				cont_block(ctx);
			} else {
				cont_syscall_block(ctx);
			}

			/* we must disallow the context switch here! */
			ctx->allow_ctx_switch = 0;

			/*
			 * When the seccomp filter is on, instead of capturing syscalls by using PTRACE_SYSCALL, the filter
			 * will generate the ptrace events. This means we allow the process to run using PTRACE_CONT, and rely on the seccomp
			 * filter to generate the special PTRACE_EVENT_SECCOMP event once a syscall happens.
			 * This event is handled here by simply allowing the process to continue to the actual
			 * entry point of the syscall (using cont_syscall_block()) and then using the same logic as before.
			 */
			int ptrace_event = GET_PTRACE_EVENT(ctx->status);
			if (ptrace_event == PTRACE_EVENT_SECCOMP) {
				filter_on_ = TRUE;
				if (ctx->event < 0) { /* Finish handling of the signal first */
					record_event(ctx,STATE_SYSCALL_ENTRY);
				}
				/* We require an extra continue, to get to the actual syscall */
				// TODO: What if there's a signal in between?
				cont_syscall_block(ctx);
			} else if (ptrace_event == PTRACE_EVENT_CLONE ||
					   ptrace_event == PTRACE_EVENT_FORK) { /* clone(),fork() are handled differently with seccomp TODO: vfork() */
				debug("Handling ptrace event: %d", GET_PTRACE_EVENT(ctx->status));
				record_event(ctx, STATE_SYSCALL_ENTRY);
				handle_ptrace_event(&ctx);
				rec_process_syscall(ctx,SYS_clone,rr_flags);
				record_event(ctx, STATE_SYSCALL_EXIT);
				break;
			} else if (ptrace_event) { // TODO: this should only be the exit event really...
				debug("Handling ptrace event: %d", GET_PTRACE_EVENT(ctx->status));
				record_event(ctx, STATE_SYSCALL_EXIT);
				handle_ptrace_event(&ctx);
				break;
			}

			if (ctx->event == SIG_SEGV_MMAP_READ || ctx->event == SIG_SEGV_MMAP_WRITE) {

				// state might be overwritten if a signal occurs
			} else if (ctx->event == SIG_SEGV_RDTSC || ctx->event == USR_SCHED) {
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
				 * fully process the sigreturn system call.
				 */
				int orig_event = ctx->event;
				record_event(ctx, STATE_SYSCALL_ENTRY);
				/* do another step */
				cont_syscall_block(ctx);

				assert(ctx->child_sig == 0);
				/* the next event is -1 -- how knows why?*/
				assert(ctx->event == -1);
				ctx->event = orig_event;
				record_event(ctx, STATE_SYSCALL_EXIT);
				ctx->allow_ctx_switch = 0;

				/* here we can continue normally */
				break;

			} else if (ctx->event > 0) {
				ctx->exec_state = EXEC_STATE_ENTRY_SYSCALL;

				/* this is a wired state -- no idea why it works */
			} else if (ctx->event == SYS_restart_syscall) {
				/* Syscalls like nanosleep(), poll() which can't be
				 * restarted with their original arguments use the
				 * ERESTART_RESTARTBLOCK code.
				 *
				 * ---------------->
				 * Kernel will execute restart_syscall() instead,
				 * which changes arguments before restarting syscall.
				 * <----------------
				 *
				 * SA_RESTART is ignored (assumed not set) similarly
				 * to ERESTARTNOHAND. (Kernel can't honor SA_RESTART
				 * since restart data is saved in "restart block"
				 * in task struct, and if signal handler uses a syscall
				 * which in turn saves another such restart block,
				 * old data is lost and restart becomes impossible)
				 */
				debug("Thread %d: restarting syscall %d",ctx->child_tid,ctx->last_syscall);
				/*
				 * From errno.h:
				 * These should never be seen by user programs.  To return
				 * one of ERESTART* codes, signal_pending() MUST be set.
				 * Note that ptrace can observe these at syscall exit tracing,
				 * but they will never be left for the debugged user process to see.
				 */
				ctx->exec_state = EXEC_STATE_ENTRY_SYSCALL;
				/* We do not record the syscall_restart event as it will not appear in the replay */
				break;
				/* we sould never come here */
			} else {
				assert(1==0);
			}

			record_event(ctx, STATE_SYSCALL_ENTRY);
			break;
		}

		case EXEC_STATE_ENTRY_SYSCALL:
		{
			/* continue and execute the system call */
			ctx->allow_ctx_switch = allow_ctx_switch(ctx,ctx->event);
			cont_nonblock(ctx);
			ctx->exec_state = EXEC_STATE_IN_SYSCALL;
			break;
		}

		case EXEC_STATE_IN_SYSCALL:
		{
			int ret;
			/*
			 * Wait for the system call to return in case of a write,
			 * but only for a certain timeout to prevent livelocks if
			 * the write system call blocks.
			 */
			switch (ctx->event) {
			case SYS_write:
			{
				ret = wait_block_timeout(ctx, MAX_WAIT_TIMEOUT_SYS_WRITE_US);
				/*
				 * proceed with a different thread if the system call takes
				 * too long to finish
				 * */
				if (ret <= 0) {
					ctx->allow_ctx_switch=1;
				}
				break;
			}
			
			default:
			{
				ret = wait_nonblock(ctx);
				break;
			}
			}

			if (ret) {
				ctx->exec_state = EXEC_STATE_IN_SYSCALL_DONE;
				ctx->allow_ctx_switch = 0;
			}
			break;
		}

		case EXEC_STATE_IN_SYSCALL_DONE:
		{
			assert(signal_pending(ctx->status) == 0);

			struct user_regs_struct regs;
			read_child_registers(ctx->child_tid,&regs);
			int syscall = regs.orig_eax;
			int retval = regs.eax;

			/* we received a signal while in the system call and send it right away*/
			/* we have already sent the signal and process sigreturn */
			if (ctx->event == SYS_sigreturn) {
				assert(1==0);
			}

			// if the syscall is about to be restarted, save the last syscall performed by it.
			if (syscall != SYS_restart_syscall &&
			    (retval == ERESTART_RESTARTBLOCK || retval == ERESTARTNOINTR)) {
				ctx->last_syscall = syscall;
			}

			handle_ptrace_event(&ctx);

			if ((ctx != NULL) && (ctx->event != SYS_vfork)) {
				ctx->child_sig = signal_pending(ctx->status);
				// a syscall_restart ending is equivalent to the restarted syscall ending
				if (syscall == SYS_restart_syscall) {
					debug("restart_syscall exit");
					syscall = ctx->last_syscall;
					ctx->event = syscall;
				}
				// no need to process the syscall in case its restarted
				// this will be done in the exit from the restart_syscall
				if (!(retval == ERESTART_RESTARTBLOCK || retval == ERESTARTNOINTR))
					rec_process_syscall(ctx, syscall, rr_flags);
				record_event(ctx, STATE_SYSCALL_EXIT);
				ctx->exec_state = EXEC_STATE_START;
				ctx->allow_ctx_switch = 1;
			}

			break;
		}

		default:
		errx(1, "Unknown execution state: %x -- bailing out\n", ctx->exec_state);
			break;
		}
	} /* while loop */

}
