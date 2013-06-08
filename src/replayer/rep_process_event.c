/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syscall.h>

#include <linux/futex.h>
#include <linux/net.h>
#include <linux/mman.h>
#include <linux/prctl.h>
#include <linux/shm.h>
#include <linux/sem.h>
#include <linux/soundcard.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/quota.h>
#include <sys/socket.h>

#include <drm/radeon_drm.h>
#include <drm/i915_drm.h>

#include "rep_process_event.h"
#include "rep_sched.h"
#include "replayer.h"

#include "../share/dbg.h"
#include "../share/ipc.h"
#include "../share/sys.h"
#include "../share/trace.h"
#include "../share/util.h"
#include "../share/shmem.h"
#include "../share/wrap_syscalls.h"

struct syscall_def {
	/* See syscall_defs.h for documentation on these values. */
	enum { rep_UNDEFINED,	/* NB: this symbol must have the value 0 */
	       rep_EMU,
	       rep_EXEC,
	       rep_EXEC_RET_EMU,
	       rep_IRREGULAR
	} type;
	/* Not meaningful for rep_IRREGULAR. */
	size_t num_emu_args;
};

#define SYSCALL_NUM(_name)__NR_##_name
#define SYSCALL_DEF(_type, _name, _num_args)			\
	[SYSCALL_NUM(_name)] = { rep_##_type, _num_args },

static struct syscall_def syscall_table[] = {
	/* Not-yet-defined syscalls will end up being type
	 * rep_UNDEFINED. */
#include "syscall_defs.h"
};
#undef SYSCALL_DEF
#undef SYSCALL_NUM

bool validate = FALSE;

/**
 * Compares the register file as it appeared in the recording phase
 * with the current register file.
 */
static void validate_args(int syscall, int state, struct context* ctx)
{
	struct user_regs_struct cur_reg;

	/* don't validate anything before execve is done as the actual
	 * process did not start prior to this point */
	if (!validate) {
		return;
	}
	read_child_registers(ctx->child_tid, &cur_reg);
	int err = compare_register_files("syscall now", &cur_reg, "recorded",
					 &(ctx->trace.recorded_regs), 1, 0);
	if (err) {
		fatal("[syscall number %d, state %d, trace file line %d]\n",
		      syscall, state, get_trace_file_lines_counter());
	}
	/* TODO: add perf counter validations (hw int, page faults, insts) */
}

/**
 * Proceeds until the next system call, which is not executed.
 */
static void goto_next_syscall_emu(struct context *ctx)
{
	sys_ptrace_sysemu(ctx->child_tid);
	sys_waitpid(ctx->child_tid, &(ctx->status));

	int sig = signal_pending(ctx->status);
	/* SIGCHLD is pending, do not deliver it, wait for it to
	 * appear in the trace SIGCHLD is the only signal that should
	 * ever be generated as all other signals are emulated! */
	if (sig == SIGCHLD) {
		goto_next_syscall_emu(ctx);
		return;
	} else if (SIGTRAP == sig) {
		fatal("SIGTRAP while entering syscall ... were you using a debugger? If so, the current syscall needs to be made interruptible");
	} else if (sig) {
		fatal("Replay got unrecorded signal %d", sig);
	}

	/* check if we are synchronized with the trace -- should never
	 * fail */
	const int rec_syscall = ctx->trace.recorded_regs.orig_eax;
	const int current_syscall = read_child_orig_eax(ctx->child_tid);

	if (current_syscall != rec_syscall) {
		/* this signal is ignored and most likey delivered
		 * later, or was already delivered earlier */
		/* TODO: this code is now obselete */
		if (WSTOPSIG(ctx->status) == SIGCHLD) {
			debug("do we come here?\n");
			/*ctx->replay_sig = SIGCHLD; // remove that if
			 * spec does not work anymore */
			goto_next_syscall_emu(ctx);
			return;
		}

		fatal("goto_next_syscall_emu: stop reason: %x signal: %d pending sig: %d\n"
		      "Internal error: syscalls out of sync: rec: %d  now: %d  time: %u\n"
		      "ptrace_event: %x",
		      ctx->status, WSTOPSIG(ctx->status), ctx->child_sig,
		      rec_syscall, current_syscall, ctx->trace.global_time,
		      GET_PTRACE_EVENT(ctx->status));
	}
	ctx->child_sig = 0;

	/* We are now at the entry point to a syscall, set the wrapper
	 * record buffer size to 0 (if needed)*/
	rep_child_buffer0(ctx);
}

/**
 *  Step over the system call to be able to reuse PTRACE_SYSTEM call
 */
static void finish_syscall_emu(struct context *ctx)
{
	struct user_regs_struct regs;
	read_child_registers(ctx->child_tid, &regs);
	sys_ptrace_sysemu_singlestep(ctx->child_tid);
	sys_waitpid(ctx->child_tid, &(ctx->status));
	write_child_registers(ctx->child_tid, &regs);

	ctx->status = 0;
}

/**
 * Proceeds until the next system call, which is being executed.
 */
void __ptrace_cont(struct context *ctx)
{
	sys_ptrace_syscall(ctx->child_tid);
	sys_waitpid(ctx->child_tid, &ctx->status);

	ctx->child_sig = signal_pending(ctx->status);
	sys_ptrace(PTRACE_GETREGS, ctx->child_tid, NULL, &ctx->child_regs);
	ctx->event = ctx->child_regs.orig_eax;

	/* check if we are synchronized with the trace -- should never fail */
	int rec_syscall = ctx->trace.recorded_regs.orig_eax;
	int current_syscall = ctx->child_regs.orig_eax;

	if (current_syscall != rec_syscall) {
		/* this signal is ignored and most likey delivered
		 * later, or was already delivered earlier */
		if (WSTOPSIG(ctx->status) == SIGCHLD) {
			__ptrace_cont(ctx);
			ctx->child_sig = 0;
			return;
		}
		fatal("\n"
		      "stop reason: %x :%d  pending sig: %d\n"
		      "recorded eip: 0x%lx;  current eip: 0x%lx\n"
		      "Internal error: syscalls out of sync: rec: %d  now: %d\n",
		      ctx->status, WSTOPSIG(ctx->status), ctx->child_sig,
		      ctx->trace.recorded_regs.eip, ctx->child_regs.eip,
		      rec_syscall, current_syscall);
	}

	/*assert(ctx->child_sig == 0);*/
	/* we should not have a signal pending here -- if there is one
	 * pending nevertheless, we do not deliver it to the
	 * application. This ensures that the behavior remains the
	 * same (this is probably irrelevant with signal emulation)
	 */
	ctx->child_sig = 0;

	/* We are now at the entry point to a syscall, set the wrapper
	 * record buffer size to 0 (if needed)*/
	rep_child_buffer0(ctx);
}

void rep_process_flush(struct context* ctx) {
	// read the flushed buffer
	size_t buffer_size;
	int* rec_addr;
	int* buffer0 = read_raw_data(&(ctx->trace), &buffer_size,
				     (void*)&rec_addr);
	int* buffer = buffer0;
	int offset = sizeof(int);
	int record_size;

	assert(rec_addr == ctx->syscall_wrapper_cache_child);
	/* the recorded size should be the buffer size minus the first cell */
	assert(buffer[0] == buffer_size - sizeof(int));

	buffer++;
	/* for each record */
	while (buffer_size > offset) {
		int syscall = buffer[0];
		record_size = buffer[1];
		int ret = buffer[2];
		/* Allow the child to run up to the recorded syscall */
		sys_ptrace_sysemu_sig(ctx->child_tid, 0);
		sys_waitpid(ctx->child_tid, &(ctx->status));
		if (signal_pending(ctx->status)) {
			fatal("While pushing wrapped syscall content, received signal %d",
			      signal_pending(ctx->status));
		}
		if (syscall == SYS_futex) {
			/* replay *uaddr for futex */
			write_child_data(ctx, sizeof(int),
					 (void*)buffer[3], (void*)buffer[4]);
		}
		int* size_ptr =	read_child_data(
			ctx, sizeof(int), ctx->syscall_wrapper_cache_child);
		assert(*size_ptr == offset - sizeof(int));
		sys_free((void**)&size_ptr);
		struct user_regs_struct regs;
		read_child_registers(ctx->child_tid,&regs);
		/*assert(regs.orig_eax == syscall);*/
		/* Just push in the portion of the buffer needed, the
		 * wrapper code will copy all that is needed to the
		 * child buffers! :)
		 *
		 * TODO: map syscall_wrapper_cache as shared and do
		 * writing faster
		 */
		 /*memcpy(ctx->syscall_wrapper_cache + offset, buffer, record_size);*/
		debug("Pushing cache buffer: %d bytes at %p",
		      record_size,
		      (void*)ctx->syscall_wrapper_cache_child + offset);
		write_child_data(
			ctx, record_size,
			(void*)ctx->syscall_wrapper_cache_child + offset,
			buffer);
		/* Set return value */
		write_child_eax(ctx->child_tid,ret);
		/* Make buffer and offset point to the next syscall record */
		buffer = (void*)buffer + record_size;
		offset += record_size;
		/* Finish the emulation */
		finish_syscall_emu(ctx);
	}
	sys_free((void**)&buffer0);
}

static void enter_syscall_emu(struct context* ctx, int syscall)
{
	goto_next_syscall_emu(ctx);
	validate_args(syscall, STATE_SYSCALL_ENTRY, ctx);
}

static void exit_syscall_emu(struct context* ctx,
			     int syscall, int num_emu_args)
{
	int i;

	for (i = 0; i < num_emu_args; ++i) {
		set_child_data(ctx);
	}
	set_return_value(ctx);
	validate_args(syscall, STATE_SYSCALL_EXIT, ctx);
	finish_syscall_emu(ctx);
}

static void enter_syscall_exec(struct context* ctx, int syscall)
{
	__ptrace_cont(ctx);
	validate_args(syscall, STATE_SYSCALL_ENTRY, ctx);
}

enum { DONT_EMULATE_RETURN = 0, EMULATE_RETURN = 1 };
static void exit_syscall_exec(struct context* ctx, int syscall,
			      int num_emu_args, int emu_ret)
{
	int i;

	__ptrace_cont(ctx);
	for (i = 0; i < num_emu_args; ++i) {
		set_child_data(ctx);
	}
	if (emu_ret) {
		set_return_value(ctx); 
	}
	validate_args(syscall, STATE_SYSCALL_EXIT, ctx);
}

static void process_clone(struct context* ctx,
			  struct trace_frame* trace, int state)
{
	int syscall = SYS_clone;
	pid_t tid = ctx->child_tid;

	if (state == STATE_SYSCALL_ENTRY) {
		struct trace_frame next_trace;
		peek_next_trace(&next_trace);
		if (next_trace.recorded_regs.eax < 0) {
			/* creation failed, emulate it */
			enter_syscall_emu(ctx, SYS_clone);
			return;
		}
	}

	if (state == STATE_SYSCALL_EXIT) {
		if (trace->recorded_regs.eax < 0) {
			/* creation failed, emulate it */
			exit_syscall_emu(ctx, SYS_clone, 0);
			return;
		}
	}

	if (state == STATE_SYSCALL_ENTRY) {
		enter_syscall_exec(ctx, SYS_clone);
	} else {
		/* execute the system call */
		__ptrace_cont(ctx);
		/* wait for the signal that a new process is created */
		__ptrace_cont(ctx);

		pid_t new_tid = sys_ptrace_getmsg(tid);

		/* wait until the new thread is ready */
		int status;
		sys_waitpid(new_tid, &status);

		rep_sched_register_thread(new_tid, trace->recorded_regs.eax);

		/* FIXME: what if registers are non-null and contain
		 * an invalid address? */
		set_child_data(ctx);
		set_child_data(ctx);

		size_t size;
		void* rec_addr;
		void* data = read_raw_data(&(ctx->trace), &size, &rec_addr);
		if (data != NULL ) {
			write_child_data_n(new_tid, size, (void*)rec_addr, data);
			sys_free((void**) &data);
		}

		data = read_raw_data(&(ctx->trace), &size, &rec_addr);
		if (data != NULL ) {
			write_child_data_n(new_tid, size, (void*)rec_addr, data);
			sys_free((void**) &data);
		}

		data = read_raw_data(&(ctx->trace), &size, &rec_addr);
		if (data != NULL ) {
			write_child_data_n(new_tid, size, (void*)rec_addr, data);
			sys_free((void**) &data);
		}
		/* set the ebp register to the recorded value -- it
		 * should not point to data on that is used
		 * afterwards */
		write_child_ebp(tid, trace->recorded_regs.ebp);
		set_return_value(ctx);
		validate_args(syscall, state, ctx);
	}

}

static void process_ioctl(struct context* ctx, int state,
			  struct rep_trace_step* step)
{
	pid_t tid = ctx->child_tid;
	int request;

	step->params.syscall.emu = 1;
	step->params.syscall.emu_ret = 1;

	if (state == STATE_SYSCALL_ENTRY) {
		step->action = TSTEP_ENTER_SYSCALL;
		return;
	}

	step->action = TSTEP_EXIT_SYSCALL;
	if ((request = read_child_ecx(tid)) & _IOC_WRITE) {
		switch (request) {
		case TCGETS:
		case FIONREAD:
		case TIOCGWINSZ:
		case TIOCGPGRP:
			step->params.syscall.num_emu_args = 1;
			break;
		case DRM_IOCTL_VERSION:
			step->params.syscall.num_emu_args = 4;
			break;
		case DRM_IOCTL_I915_GEM_PWRITE:
			step->params.syscall.num_emu_args = 2;
			break;
		case DRM_IOCTL_GET_MAGIC:
		case DRM_IOCTL_RADEON_INFO:
		case DRM_IOCTL_RADEON_GEM_CREATE:
			print_register_file_tid(tid);
			step->params.syscall.num_emu_args = 1;
			break;
		default:
			print_register_file_tid(tid);
			fatal("Unknown ioctl: %x", request);
		}
	}
}

void process_ipc(struct context* ctx, struct trace_frame* trace, int state)
{
	int tid = ctx->child_tid;
	int call = trace->recorded_regs.ebx;
	/* TODO: ipc may be completely emulated */
	if (state == STATE_SYSCALL_ENTRY) {
		switch (call) {
		case MSGRCV:
		case SEMGET:
		case SEMCTL:
		case SEMOP:
			enter_syscall_emu(ctx, SYS_ipc);
			break;
		default:
			enter_syscall_exec(ctx, SYS_ipc);
			break;
		}
	} else {
		switch (call) {
		/* int shmget(key_t key, size_t size, int shmflg); */
		case SHMGET: {
			__ptrace_cont(ctx);
			shmem_store_key(trace->recorded_regs.eax,
					read_child_eax(tid));
			set_return_value(ctx);
			validate_args(SYS_ipc, state, ctx);
			break;
		}
		/* void *shmat(int shmid, const void *shmaddr, int shmflg) */
		case SHMAT: {
			struct user_regs_struct regs;
			read_child_registers(tid, &regs);
			int orig_shmemid = regs.ecx;
			int shmid = shmem_get_key(regs.ecx);
			write_child_ecx(tid, shmid);
			/* demand the mapping to be at the
			 * address supplied by the replay */
			size_t size;
			void* rec_addr;
			long* map_addr =
				read_raw_data(trace, &size, (void*)&rec_addr);
			assert(rec_addr == (void*)regs.esi);
			/* hint sits at edi */
			write_child_edi(tid, *map_addr);
			__ptrace_cont(ctx);
			read_child_registers(tid, &regs);
			/* put the key back */
			regs.ecx = orig_shmemid;
			/* restore the hint */
			regs.edi = trace->recorded_regs.edi;
			write_child_registers(tid, &regs);
			void* result =
				(void*)read_child_data_word(tid,
							    (void*)regs.esi);
			(void)result;
			assert(*map_addr == (long)result);
			/* TODO: remove this once this call is
			 * emulated */
			if (*map_addr > 0) {
				/* to prevent direct memory access to
				 * shared memory with non recorded
				 * processes */
				mprotect_child_region(ctx,
						      (void*)*map_addr,
						      PROT_NONE);
			}
			sys_free((void**)&map_addr);
			validate_args(SYS_ipc, state, ctx);
			break;
		}

		/* int shmctl(int shmid, int cmd, struct shmid_ds *buf); */
		case SHMCTL: {
			int orig_shmemid = read_child_ecx(tid);
			int shmid = shmem_get_key(read_child_ecx(tid));

			write_child_ecx(tid, shmid);
			__ptrace_cont(ctx);
			write_child_ecx(tid, orig_shmemid);
			set_child_data(ctx);
			validate_args(SYS_ipc, state, ctx);
			break;
		}

		/* ssize_t msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg); */
		case MSGRCV:
			exit_syscall_emu(ctx, SYS_ipc, 1);
			break;

		/* int shmdt(const void *shmaddr); */
		case SHMDT:
			exit_syscall_exec(ctx, SYS_ipc, 0, EMULATE_RETURN);
			break;

		case SEMGET:
		/* int semop(int semid, struct sembuf *sops, unsigned nsops); */
		case SEMOP:
			exit_syscall_emu(ctx, SYS_ipc, 0);
			break;

		/* int semctl(int semid, int semnum, int cmd, union semnum); */
		case SEMCTL: {
			int cmd = trace->recorded_regs.edx;
			int num_emu_args;

			switch (cmd) {
			case IPC_SET:
			case IPC_RMID:
			case GETNCNT:
			case GETPID:
			case GETVAL:
			case GETZCNT:
			case SETALL:
			case SETVAL:
				num_emu_args = 0;
				break;
			case IPC_STAT:
			case SEM_STAT:
			case IPC_INFO:
			case SEM_INFO:
			case GETALL:
				num_emu_args = 1;
				break;
			default:
				fatal("Unknown semctl command %d", cmd);
				break;
			}
			exit_syscall_emu(ctx, SYS_ipc, num_emu_args);
		}

		default:
			fatal("Unknown ipc call: %d", call);
		}
	}
}

static void process_mmap2(struct context* ctx,
			  struct trace_frame* trace, int state)
{
	int syscall = SYS_mmap2;
	int tid = ctx->child_tid;

	if (state == STATE_SYSCALL_ENTRY) {
		struct trace_frame next;
		peek_next_trace(&next);
		if (SYSCALL_FAILED(next.recorded_regs.eax)) {
			/* failed mapping, emulate */
			enter_syscall_emu(ctx, SYS_mmap2);
		} else {
			enter_syscall_exec(ctx, SYS_mmap2);
		}
		return;
	}

	if (SYSCALL_FAILED(trace->recorded_regs.eax)) {
		/* failed mapping, emulate */
		exit_syscall_emu(ctx, SYS_mmap2, 0);
		return;
	}

	struct user_regs_struct regs;
	read_child_registers(tid, &regs);

	if (!(regs.esi & MAP_ANONYMOUS)) {
		struct mmapped_file file;
		read_next_mmapped_file_stats(&file);
		assert(file.time == trace->global_time);

		struct user_regs_struct orig_regs;
		memcpy(&orig_regs, &regs, sizeof(orig_regs));

		int prot = regs.edx;
		if (strstr(file.filename, WRAP_SYSCALLS_LIB_FILENAME)
		    && (prot & PROT_EXEC) ) {
			/* Note: the library get loaded several times,
			 * we need the (hopefully one) copy that is
			 * executable */
			ctx->syscall_wrapper_start = file.start;
			ctx->syscall_wrapper_end = file.end;
		}

		/* hint the kernel where to allocate the
		 * page */
		regs.ebx = ctx->trace.recorded_regs.eax;

		/* XXX refactor me, nesting too deep */

		/* For shared mmaps: verify
		 * modification time */
		if (regs.esi & MAP_SHARED) {
			if (strstr(file.filename,
				   WRAP_SYSCALLS_CACHE_FILENAME_PREFIX)) {
				/* record cache */
				ctx->syscall_wrapper_cache_child =
					(void*)regs.ebx;
			} else if (strcmp(file.filename, "/home/user/.cache/dconf/user") != 0 && 	// not dconf   (proxied)
				   strstr(file.filename, "sqlite") == NULL) {				  				// not sqlite  (private)
				struct stat st;
				stat(file.filename, &st);
				if (file.stat.st_mtim.tv_sec != st.st_mtim.tv_sec || file.stat.st_mtim.tv_nsec != st.st_mtim.tv_nsec) {
					log_warn("Shared file %s timestamp changed! This may cause divergence in case the file is shared with a non-recorded process.", file.filename);
				}
			}
		}
		/* set anonymous flag */
		regs.esi |= MAP_ANONYMOUS;
		regs.esi |= MAP_FIXED;
		regs.edi = -1;
		regs.ebp = 0;
		write_child_registers(tid, &regs);

		/* execute the mmap */
		__ptrace_cont(ctx);

		/* restore original register state */
		orig_regs.eax = ctx->child_regs.eax;
		write_child_registers(tid, &orig_regs);

		/* check if successful */
		validate_args(syscall, state, ctx);

		/* inject recorded data */
		set_child_data(ctx);

	} else {
		struct user_regs_struct orig_regs;
		memcpy(&orig_regs, &regs, sizeof(struct user_regs_struct));

		/* hint the kernel where to allocate the page */
		regs.ebx = ctx->trace.recorded_regs.eax;
		regs.esi |= MAP_FIXED;

		write_child_registers(tid, &regs);
		__ptrace_cont(ctx);

		/* restore original register state */
		orig_regs.eax = ctx->child_regs.eax;
		write_child_registers(tid, &orig_regs);

		validate_args(syscall, state, ctx);
		debug("%d[time=%d]: mmapped anonymous with flags %x to address %p\n",
		      ctx->child_tid, trace->global_time, orig_regs.esi,orig_regs.eax);
	}
}

static void process_socketcall(struct context* ctx, int state,
			       struct rep_trace_step* step)
{
	int call;

	step->params.syscall.emu = 1;
	step->params.syscall.emu_ret = 1;

	if (state == STATE_SYSCALL_ENTRY) {
		step->action = TSTEP_ENTER_SYSCALL;
		return;
	}

	step->action = TSTEP_EXIT_SYSCALL;
	switch ((call = read_child_ebx(ctx->child_tid))) {
		/* FIXME: define a SSOT for socketcall record and
		 * replay data, a la syscall_defs.h */
	case SYS_SOCKET:
	case SYS_CONNECT:
	case SYS_BIND:
	case SYS_LISTEN:
	case SYS_SENDMSG:
	case SYS_SEND:
	case SYS_SENDTO:
	case SYS_SETSOCKOPT:
	case SYS_SHUTDOWN:
		step->params.syscall.num_emu_args = 0;
		break;
	case SYS_GETPEERNAME:
	case SYS_GETSOCKNAME:
		step->params.syscall.num_emu_args = 2;
		break;
	case SYS_RECV:
		step->params.syscall.num_emu_args = 1;
		break;
	/* ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags); */
	case SYS_RECVMSG:
		/* write the struct msghdr data structure */
		step->params.syscall.num_emu_args = 5;
		break;

	/* int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	 *
	 * Note: The returned address is truncated if the buffer
	 * provided is too small; in this case, addrlen will return a
	 * value greater than was supplied to the call.
	 *
	 * For now we record the size of bytes that is returned by the
	 * system call. We check in the replayer, if the buffer was
	 * actually too small and throw an error there.
	 */
	case SYS_ACCEPT:
		/* FIXME: not quite sure about socket_addr */
		step->params.syscall.num_emu_args = 2;
		break;

	case SYS_SOCKETPAIR:
	case SYS_GETSOCKOPT:
		step->params.syscall.num_emu_args = 1;
		break;

	case SYS_RECVFROM:
		step->params.syscall.num_emu_args = 3;
		break;

	default:
		fatal("Unknown socketcall: %d\n", call);
	}
}

void rep_process_syscall(struct context* ctx, int redirect_stdio,
			 struct rep_trace_step* step)
{
	int syscall = ctx->trace.stop_reason;
	const struct syscall_def* def = &syscall_table[syscall];
	pid_t tid = ctx->child_tid;
	struct trace_frame* trace = &(ctx->trace);
	int state = trace->state;

	if (STATE_SYSCALL_EXIT == state
	    && SYSCALL_WILL_RESTART(trace->recorded_regs.eax)) {
		/* when a syscall exits with a restart "error", it
		 * will be restarted by the kernel with a restart
		 * syscall (see below). The child process is oblivious
		 * to this, so in the replay we need to jump directly
		 * to the exit from the restart_syscall */
		step->action = TSTEP_RETIRE;
		return;
	}

	if (SYS_restart_syscall == syscall) {
		/* the restarted syscall will be replayed by the next
		 * entry which is an exit entry for the original
		 * syscall being restarted - do nothing here. */
		step->action = TSTEP_RETIRE;
		return;
	}

	assert("Syscallno not in table, but possibly valid"
	       && syscall < ALEN(syscall_table));
	assert("Valid but unhandled syscallno"
	       && rep_UNDEFINED != def->type);

	step->params.syscall.no = syscall;

	if (rep_IRREGULAR != def->type) {
		step->params.syscall.num_emu_args = def->num_emu_args;
		step->action = STATE_SYSCALL_ENTRY == state ?
			       TSTEP_ENTER_SYSCALL : TSTEP_EXIT_SYSCALL;
		step->params.syscall.emu = rep_EMU == def->type;
		step->params.syscall.emu_ret =
			rep_EMU == def->type || rep_EXEC_RET_EMU == def->type;
		return;
	}

	assert(rep_IRREGULAR == def->type);

	/* Manual implementations of irregular syscalls. */

	switch (syscall) {
	case SYS_exit:
	case SYS_exit_group:
		step->params.syscall.emu = 0;
		assert(state == STATE_SYSCALL_ENTRY);
		step->action = TSTEP_ENTER_SYSCALL;
		return;

	case SYS_fcntl64:
		step->params.syscall.emu = 1;
		step->params.syscall.emu_ret = 1;
		if (state == 0) {
			step->action = TSTEP_ENTER_SYSCALL;
		} else {
			int cmd = read_child_ecx(tid);

			step->action = TSTEP_EXIT_SYSCALL;
			switch (cmd) {
			case F_DUPFD:
			case F_GETFD:
			case F_GETFL:
			case F_SETFL:
			case F_SETFD:
			case F_SETOWN:
				step->params.syscall.num_emu_args = 0;
				break;
			case F_SETLK:
			case F_SETLK64:
			case F_SETLKW64:
			case F_GETLK:
			case F_GETLK64:
				step->params.syscall.num_emu_args = 1;
				break;
			default:
				fatal("Unknown fcntl64 command: %d", cmd);
			}
		}
		return;

	case SYS_futex:
		step->params.syscall.emu = 1;
		step->params.syscall.emu_ret = 1;
		if (state == STATE_SYSCALL_ENTRY) {
			step->action = TSTEP_ENTER_SYSCALL;
		} else {
			int op = read_child_ecx(tid) & FUTEX_CMD_MASK;

			step->action = TSTEP_EXIT_SYSCALL;
			switch (op) {
			case FUTEX_WAKE:
			case FUTEX_WAIT_BITSET:
			case FUTEX_WAIT:
			case FUTEX_UNLOCK_PI:
				step->params.syscall.num_emu_args = 1;
				break;
			case FUTEX_CMP_REQUEUE:
			case FUTEX_WAKE_OP:
			case FUTEX_CMP_REQUEUE_PI:
			case FUTEX_WAIT_REQUEUE_PI:
				step->params.syscall.num_emu_args = 2;
				break;
			default:
				fatal("op: %d futex_wait: %d \n",
				      op, FUTEX_WAIT);
			}
		}
		return;

	case SYS_ioctl:
		return process_ioctl(ctx, state, step);

	case SYS_nanosleep:
		step->params.syscall.emu = 1;
		step->params.syscall.emu_ret = 1;
		if (STATE_SYSCALL_ENTRY == state) {
			step->action = TSTEP_ENTER_SYSCALL;
		} else {
			step->action = TSTEP_EXIT_SYSCALL;
			step->params.syscall.num_emu_args =
				(trace->recorded_regs.ecx != 0) ? 1 : 0;
		}
		return;

	case SYS_quotactl:
		step->params.syscall.emu = 1;
		step->params.syscall.emu_ret = 1;
		if (state == STATE_SYSCALL_ENTRY) {
			step->action = TSTEP_ENTER_SYSCALL;
		} else {
			int cmd = read_child_ebp(ctx->child_tid);

			step->action = TSTEP_EXIT_SYSCALL;
			switch (cmd & SUBCMDMASK) {
			case Q_GETQUOTA:
			case Q_GETINFO:
			case Q_GETFMT:
				step->params.syscall.num_emu_args = 1;
				break;
			default:
				step->params.syscall.num_emu_args = 0;
			}
		}
		return;

	case SYS_read:
		step->params.syscall.emu = 1;
		step->params.syscall.emu_ret = 1;
		if (STATE_SYSCALL_ENTRY == state) {
			step->action = TSTEP_ENTER_SYSCALL;
		} else {
			step->action = TSTEP_EXIT_SYSCALL;
			step->params.syscall.num_emu_args =
				(trace->recorded_regs.eax > 0) ? 1 : 0;
		}
		return;

	case SYS_socketcall:
		return process_socketcall(ctx, state, step);

	case SYS_write:
		step->params.syscall.num_emu_args = 0;
		step->params.syscall.emu = 1;
		step->params.syscall.emu_ret = 1;
		if (state == STATE_SYSCALL_ENTRY) {
			step->action = TSTEP_ENTER_SYSCALL;
		} else {
			step->action = TSTEP_EXIT_SYSCALL;
			/* XXX technically this will print the output
			 * before we reach the interrupt.  That could
			 * maybe cause issues in the future. */
			if (redirect_stdio) {
				/* print output intended for
				 * stdout/stderr */
				struct user_regs_struct regs;
				read_child_registers(ctx->child_tid, &regs);
				int fd = regs.ebx;
				if (fd == STDOUT_FILENO
				    || fd == STDERR_FILENO) {
					size_t len = regs.edx;
					void* addr = (void*) regs.ecx;
					void* buf = read_child_data(ctx,
								    len, addr);
					if (len != write(fd, buf, len)) {
						fatal("Couldn't write stdio");
					}
					sys_free(&buf);
				}
			}
		}
		return;

	default:
		break;
	}

	/* TODO: irregular syscalls that don't understand
	 * trace_step */
	step->action = TSTEP_RETIRE;

	switch (syscall) {

	case SYS_clone:
		process_clone(ctx, trace, state);
		break;

	case SYS_execve:
		if (state == STATE_SYSCALL_ENTRY) {
			enter_syscall_exec(ctx, syscall);
		} else {
			validate = TRUE;

			/* we need an additional ptrace syscall, since
			 * ptrace is setup with PTRACE_O_TRACEEXEC */
			__ptrace_cont(ctx);

			int check = read_child_ebx(tid);
			/* if the execve comes from a vfork system
			 * call the ebx register is not zero. in this
			 * case, no recorded data needs to be
			 * injected */
			if (check == 0) {
				size_t size;
				void* rec_addr;
				void* data = read_raw_data(&(ctx->trace),
							   &size, &rec_addr);
				if (data != NULL ) {
					write_child_data(
						ctx, size, (void*)rec_addr,
						data);
					sys_free((void**) &data);
				}
			}

			set_return_value(ctx);
			validate_args(syscall, state, ctx);
		}
		break;

	case SYS_ipc:
		process_ipc(ctx, trace, state);
		break;

	case SYS_mmap2:
		process_mmap2(ctx, trace, state);
		break;

	case SYS_mremap:
		if (state == STATE_SYSCALL_ENTRY) {
			enter_syscall_exec(ctx, syscall);
		} else {
			/* By using a fixed address remapping we can
			 * be sure that the mappings remain identical
			 * in the record and replay/
			 */
			struct user_regs_struct orig_regs;
			read_child_registers(ctx->child_tid, &orig_regs);

			struct user_regs_struct tmp_regs;
			memcpy(&tmp_regs, &orig_regs, sizeof(tmp_regs));
			/* set mapping to fixed and initialize the new
			 * address with the recorded address
			 */

			/* is hack is necessary, since mremap does not
			 * like the FIXED flag if source and
			 * destination address are the same */
			if (orig_regs.ebx != ctx->trace.recorded_regs.eax) {
				tmp_regs.esi |= MREMAP_FIXED;
				tmp_regs.edi = ctx->trace.recorded_regs.eax;
			}

			write_child_registers(ctx->child_tid, &tmp_regs);

			__ptrace_cont(ctx);
			/* obtain the new address and reset to the old
			 * register values */
			read_child_registers(ctx->child_tid, &tmp_regs);

			orig_regs.eax = tmp_regs.eax;
			write_child_registers(ctx->child_tid, &orig_regs);
			validate_args(syscall, state, ctx);
		}
		break;

	case SYS_setpgid:
		if (state == STATE_SYSCALL_ENTRY) {
			enter_syscall_emu(ctx, SYS_setpgid);
		} else {
			write_child_ebx(ctx->child_tid,
					ctx->trace.recorded_regs.ebx);
			exit_syscall_emu(ctx, SYS_setpgid, 0);
		}
		break;

	case SYS_sigreturn:
	case SYS_rt_sigreturn:
		if (state == STATE_SYSCALL_ENTRY) {
			enter_syscall_emu(ctx, syscall);
		} else {
			write_child_main_registers(ctx->child_tid,
						   &trace->recorded_regs);
			finish_syscall_emu(ctx);
		}
		break;

	case SYS_vfork:
		if (state == STATE_SYSCALL_ENTRY) {
			/* go to the system call */
			__ptrace_cont(ctx);
			if (PTRACE_EVENT_VFORK ==
			    GET_PTRACE_EVENT(ctx->status)) {
				unsigned long new_tid = sys_ptrace_getmsg(tid);
				/* wait until the new thread is ready */
				int status;
				sys_waitpid(new_tid, &status);

				struct trace_frame next_trace;
				peek_next_trace(&next_trace);
				rep_sched_register_thread(new_tid,
							  next_trace.tid);
			}
			validate_args(syscall, state, ctx);
		} else {
			exit_syscall_exec(ctx, syscall, 0, EMULATE_RETURN);
		}
		break;

	default:
		fatal("Unhandled  irregular syscall %d", syscall);
	}
}
