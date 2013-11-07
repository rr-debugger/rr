/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

//#define DEBUGTAG "ProcessSyscallRep"

#include "rep_process_event.h"

#define _GNU_SOURCE

/* XXX the drm/ headers are broken, work around them */
#include <stddef.h>
#include <stdint.h>

#include <assert.h>
#include <drm/i915_drm.h>
#include <drm/radeon_drm.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <linux/net.h>
#include <linux/mman.h>
#include <linux/prctl.h>
#include <linux/shm.h>
#include <linux/sem.h>
#include <linux/soundcard.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syscall.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/quota.h>
#include <sys/socket.h>

#include "rep_sched.h"
#include "replayer.h"
#include "../share/dbg.h"
#include "../share/ipc.h"
#include "../share/sys.h"
#include "../share/task.h"
#include "../share/trace.h"
#include "../share/util.h"
#include "../share/shmem.h"
#include "../share/syscall_buffer.h"

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

extern bool validate;

/**
 * Compares the register file as it appeared in the recording phase
 * with the current register file.
 */
static void validate_args(int syscall, int state, struct task* t)
{
	/* don't validate anything before execve is done as the actual
	 * process did not start prior to this point */
	if (!validate) {
		return;
	}
	assert_child_regs_are(t, &t->trace.recorded_regs, syscall, state);
}

/**
 * Proceeds until the next system call, which is not executed.
 */
static void goto_next_syscall_emu(struct task *t)
{
	sys_ptrace_sysemu(t->tid);
	sys_waitpid(t->tid, &(t->status));

	int sig = signal_pending(t->status);
	/* SIGCHLD is pending, do not deliver it, wait for it to
	 * appear in the trace SIGCHLD is the only signal that should
	 * ever be generated as all other signals are emulated! */
	if (sig == SIGCHLD) {
		goto_next_syscall_emu(t);
		return;
	} else if (SIGTRAP == sig) {
		fatal("SIGTRAP while entering syscall ... were you using a debugger? If so, the current syscall needs to be made interruptible");
	} else if (sig) {
		fatal("Replay got unrecorded signal %d", sig);
	}

	/* check if we are synchronized with the trace -- should never
	 * fail */
	const int rec_syscall = t->trace.recorded_regs.orig_eax;
	const int current_syscall = read_child_orig_eax(t->tid);

	if (current_syscall != rec_syscall) {
		/* this signal is ignored and most likey delivered
		 * later, or was already delivered earlier */
		/* TODO: this code is now obselete */
		if (WSTOPSIG(t->status) == SIGCHLD) {
			debug("do we come here?\n");
			/*t->replay_sig = SIGCHLD; // remove that if
			 * spec does not work anymore */
			goto_next_syscall_emu(t);
			return;
		}

		fatal("goto_next_syscall_emu: stop reason: %x signal: %d pending sig: %d\n"
		      "Internal error: syscalls out of sync: rec: %d  now: %d  time: %u\n"
		      "ptrace_event: %x",
		      t->status, WSTOPSIG(t->status), t->child_sig,
		      rec_syscall, current_syscall, t->trace.global_time,
		      GET_PTRACE_EVENT(t->status));
	}
	t->child_sig = 0;
}

/**
 *  Step over the system call to be able to reuse PTRACE_SYSTEM call
 */
static void finish_syscall_emu(struct task *t)
{
	struct user_regs_struct regs;
	read_child_registers(t->tid, &regs);
	sys_ptrace_sysemu_singlestep(t->tid);
	sys_waitpid(t->tid, &(t->status));
	write_child_registers(t->tid, &regs);

	t->status = 0;
}

/**
 * Proceeds until the next system call, which is being executed.
 */
void __ptrace_cont(struct task *t)
{
	sys_ptrace_syscall(t->tid);
	sys_waitpid(t->tid, &t->status);

	t->child_sig = signal_pending(t->status);
	sys_ptrace(PTRACE_GETREGS, t->tid, NULL, &t->regs);
	t->event = t->regs.orig_eax;

	/* check if we are synchronized with the trace -- should never fail */
	int rec_syscall = t->trace.recorded_regs.orig_eax;
	int current_syscall = t->regs.orig_eax;
	if (current_syscall != rec_syscall && WSTOPSIG(t->status) == SIGCHLD) {
		/* SIGCHLD can be delivered pretty much at any time
		 * during replay, and we need to ignore it since
		 * replayed signals are only emulated. */
		__ptrace_cont(t);
		t->child_sig = 0;
		return;
	}
	assert_exec(t, current_syscall == rec_syscall,
		    "Should be at %s, but instead at %s\n",
		    syscallname(rec_syscall), syscallname(current_syscall));
}

void rep_maybe_replay_stdio_write(struct task* t)
{
	struct user_regs_struct regs;
	int fd;

	if (!rr_flags()->redirect) {
		return;
	}

	read_child_registers(t->tid, &regs);

	assert(SYS_write == regs.orig_eax);

	fd = regs.ebx;
	if (fd == STDOUT_FILENO || fd == STDERR_FILENO) {
		size_t len = regs.edx;
		void* addr = (void*) regs.ecx;
		void* buf = read_child_data(t, len, addr);
		if (len != write(fd, buf, len)) {
			fatal("Couldn't write stdio");
		}
		sys_free(&buf);
	}
}

static void enter_syscall_emu(struct task* t, int syscall)
{
	goto_next_syscall_emu(t);
	validate_args(syscall, STATE_SYSCALL_ENTRY, t);
}

static void exit_syscall_emu_ret(struct task* t, int syscall)
{
	set_return_value(t);
	validate_args(syscall, STATE_SYSCALL_EXIT, t);
	finish_syscall_emu(t);
}

static void exit_syscall_emu(struct task* t,
			     int syscall, int num_emu_args)
{
	int i;

	for (i = 0; i < num_emu_args; ++i) {
		set_child_data(t);
	}
	exit_syscall_emu_ret(t, syscall);
}

static void enter_syscall_exec(struct task* t, int syscall)
{
	__ptrace_cont(t);
	validate_args(syscall, STATE_SYSCALL_ENTRY, t);
}

enum { DONT_EMULATE_RETURN = 0, EMULATE_RETURN = 1 };
static void exit_syscall_exec(struct task* t, int syscall,
			      int num_emu_args, int emu_ret)
{
	int i;

	__ptrace_cont(t);
	for (i = 0; i < num_emu_args; ++i) {
		set_child_data(t);
	}
	if (emu_ret) {
		set_return_value(t); 
	}
	validate_args(syscall, STATE_SYSCALL_EXIT, t);
}

static void init_scratch_memory(struct task* t)
{
	/* Initialize the scratchpad as the recorder did, but make it
	 * PROT_NONE. The idea is just to reserve the address space so
	 * the replayed process address map looks like the recorded
	 * process, if it were to be probed by madvise or some other
	 * means. But we make it PROT_NONE so that rogue reads/writes
	 * to the scratch memory are caught. */
	struct mmapped_file file;
	struct current_state_buffer state;
	void* map_addr;

	read_next_mmapped_file_stats(&file);

	prepare_remote_syscalls(t, &state);

	t->scratch_ptr = file.start;
	t->scratch_size = file.end - file.start;
	map_addr = (void*)remote_syscall6(
		t, &state, SYS_mmap2,
		t->scratch_ptr, t->scratch_size,
		PROT_NONE,
		MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	finish_remote_syscalls(t, &state);

	assert_exec(t, t->scratch_ptr == map_addr,
		    "scratch mapped @%p during recording, but @%p in replay",
		    file.start, map_addr);

	add_scratch(file.start, file.end - file.start);
}

/**
 * If scratch data was incidentally recorded for the current desched'd
 * but write-only syscall, then do a no-op restore of that saved data
 * to keep the trace in sync.
 *
 * Syscalls like |write()| that may-block and are wrapped in the
 * preload library can be desched'd.  When this happens, we save the
 * syscall record's "extra data" as if it were normal scratch space,
 * since it's used that way in effect.  But syscalls like |write()|
 * that don't actually use scratch space don't ever try to restore
 * saved scratch memory during replay.  So, this helper can be used
 * for that class of syscalls.
 */
static void maybe_noop_restore_syscallbuf_scratch(struct task* t)
{
	read_child_registers(t->tid, &t->regs);
	if (SYSCALLBUF_IS_IP_BUFFERED_SYSCALL(t->regs.eip, t)) {
		debug("  noop-restoring scratch for write-only desched'd %s",
		      syscallname(t->regs.orig_eax));
		set_child_data(t);
	}
}

static void process_clone(struct task* t,
			  struct trace_frame* trace, int state)
{
	int syscall = SYS_clone;
	pid_t tid = t->tid;

	if (state == STATE_SYSCALL_ENTRY) {
		struct trace_frame next_trace;
		peek_next_trace(&next_trace);
		if (next_trace.recorded_regs.eax < 0) {
			/* creation failed, emulate it */
			enter_syscall_emu(t, SYS_clone);
			return;
		}
	}

	if (state == STATE_SYSCALL_EXIT) {
		if (trace->recorded_regs.eax < 0) {
			/* creation failed, emulate it */
			exit_syscall_emu(t, SYS_clone, 0);
			return;
		}
	}

	if (state == STATE_SYSCALL_ENTRY) {
		enter_syscall_exec(t, SYS_clone);
	} else {
		/* execute the system call */
		__ptrace_cont(t);
		/* wait for the signal that a new process is created */
		__ptrace_cont(t);

		int rec_tid = trace->recorded_regs.eax;
		pid_t new_tid = sys_ptrace_getmsg(tid);
		struct task* new_task;

		/* wait until the new thread is ready */
		int status;
		sys_waitpid(new_tid, &status);

		new_task = rep_sched_register_thread(new_tid, rec_tid);

		/* FIXME: what if registers are non-null and contain
		 * an invalid address? */
		set_child_data(t);
		set_child_data(t);

		size_t size;
		void* rec_addr;
		void* data = read_raw_data(&(t->trace), &size, &rec_addr);
		if (data != NULL ) {
			write_child_data_n(new_tid, size, (void*)rec_addr, data);
			sys_free((void**) &data);
		}

		data = read_raw_data(&(t->trace), &size, &rec_addr);
		if (data != NULL ) {
			write_child_data_n(new_tid, size, (void*)rec_addr, data);
			sys_free((void**) &data);
		}

		data = read_raw_data(&(t->trace), &size, &rec_addr);
		if (data != NULL ) {
			write_child_data_n(new_tid, size, (void*)rec_addr, data);
			sys_free((void**) &data);
		}

		/* set the ebp register to the recorded value -- it
		 * should not point to data on that is used
		 * afterwards */
		write_child_ebp(tid, trace->recorded_regs.ebp);
		set_return_value(t);
		validate_args(syscall, state, t);

		init_scratch_memory(new_task);
	}

}

static void process_ioctl(struct task* t, int state,
			  struct rep_trace_step* step)
{
	pid_t tid = t->tid;
	int request;
	int dir;

	step->syscall.emu = 1;
	step->syscall.emu_ret = 1;

	if (state == STATE_SYSCALL_ENTRY) {
		step->action = TSTEP_ENTER_SYSCALL;
		return;
	}

	step->action = TSTEP_EXIT_SYSCALL;
	request = read_child_ecx(tid);
	dir = _IOC_DIR(request);

	debug("Processing ioctl 0x%x: dir 0x%x", request, dir);

	/* Process special-cased ioctls first. */
	switch (request) {
	case TCGETS:
	case TIOCINQ:
		step->syscall.num_emu_args = 1;
		return;
	}
	/* Now on to the "regular" ioctls. */

	if (!(_IOC_WRITE & dir)) {
		/* Deterministic ioctl(), no data to restore to the
		 * tracee. */
		return;
	}

	switch (request) {
	default:
		fatal("Unknown ioctl 0x%x", request);
	}
}

void process_ipc(struct task* t, struct trace_frame* trace, int state)
{
	int tid = t->tid;
	int call = trace->recorded_regs.ebx;

	/* TODO: ipc may be completely emulated */
	if (state == STATE_SYSCALL_ENTRY) {
		switch (call) {
		case MSGGET:
		case MSGRCV:
		case MSGSND:
		case SEMCTL:
		case SEMGET:
		case SEMOP:
			enter_syscall_emu(t, SYS_ipc);
			return;
		default:
			enter_syscall_exec(t, SYS_ipc);
			return;
		}
	}

	switch (call) {
	case MSGGET:
	case MSGSND:
	case SEMGET:
	/* int semop(int semid, struct sembuf *sops, unsigned nsops); */
	case SEMOP:
		exit_syscall_emu(t, SYS_ipc, 0);
		return;

	/* ssize_t msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg); */
	case MSGRCV:
		exit_syscall_emu(t, SYS_ipc, 1);
		return;

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
		}
		exit_syscall_emu(t, SYS_ipc, num_emu_args);
		return;
	}
	/* void *shmat(int shmid, const void *shmaddr, int shmflg) */
	case SHMAT: {
		struct user_regs_struct regs;
		read_child_registers(tid, &regs);
		int orig_shmemid = regs.ecx;
		int shmid = shmem_get_key(regs.ecx);
		write_child_ecx(tid, shmid);
		/* demand the mapping to be at the address supplied by
		 * the replay */
		size_t size;
		void* rec_addr;
		long* map_addr = read_raw_data(trace, &size, (void*)&rec_addr);
		assert(rec_addr == (void*)regs.esi);
		/* hint sits at edi */
		write_child_edi(tid, *map_addr);
		__ptrace_cont(t);
		read_child_registers(tid, &regs);
		/* put the key back */
		regs.ecx = orig_shmemid;
		/* restore the hint */
		regs.edi = trace->recorded_regs.edi;
		write_child_registers(tid, &regs);
		void* result = (void*)read_child_data_word(tid,
							   (void*)regs.esi);
		(void)result;
		assert(*map_addr == (long)result);
		/* TODO: remove this once this call is emulated */
		if (*map_addr > 0) {
			/* TODO: record access to shmem segments that
			 * may be shared with processes outside the rr
			 * tracee tree. */
			log_warn("Attached SysV shmem region (%p) that may be shared with outside processes.  Marking PROT_NONE so that SIGSEGV will be raised if the segment is accessed.", (void*)*map_addr);
			mprotect_child_region(t, (void*)*map_addr, PROT_NONE);
		}
		sys_free((void**)&map_addr);
		validate_args(SYS_ipc, state, t);
		return;
	}
	/* int shmctl(int shmid, int cmd, struct shmid_ds *buf); */
	case SHMCTL: {
		int orig_shmemid = read_child_ecx(tid);
		int shmid = shmem_get_key(read_child_ecx(tid));

		write_child_ecx(tid, shmid);
		__ptrace_cont(t);
		write_child_ecx(tid, orig_shmemid);
		set_child_data(t);
		validate_args(SYS_ipc, state, t);
		return;
	}
	/* int shmdt(const void *shmaddr); */
	case SHMDT:
		exit_syscall_exec(t, SYS_ipc, 0, EMULATE_RETURN);
		return;

	/* int shmget(key_t key, size_t size, int shmflg); */
	case SHMGET: {
		__ptrace_cont(t);
		shmem_store_key(trace->recorded_regs.eax, read_child_eax(tid));
		set_return_value(t);
		validate_args(SYS_ipc, state, t);
		return;
	}
	default:
		fatal("Unknown ipc call: %d", call);
	}
}

static void* finish_anonymous_mmap(struct task* t,
				   struct current_state_buffer* state,
				   struct trace_frame* trace,
				   int prot, int flags)
{
	const struct user_regs_struct* rec_regs = &trace->recorded_regs;
	/* *Must* map the segment at the recorded address, regardless
	   of what the recorded tracee passed as the |addr| hint. */
	void* rec_addr = (void*)rec_regs->eax;
	size_t length = rec_regs->ecx;
	/* These are supposed to be (-1, 0) respectively, but use
	 * whatever the tracee passed to avoid stirring up trouble. */
	int fd = rec_regs->edi;
	off_t offset = rec_regs->ebp;
	return (void*)remote_syscall6(t, state, SYS_mmap2,
				      rec_addr, length, prot,
				      /* Tell the kernel to take
				       * |rec_addr| seriously. */
				      flags | MAP_FIXED,
				      fd, offset);
}

static void* finish_copied_mmap(struct task* t,
				struct current_state_buffer* state,
				struct trace_frame* trace,
				int prot, int flags,
				const struct mmapped_file* file)
{
	void* mapped_addr = finish_anonymous_mmap(t, state, trace, prot,
						  /* The restored region
						   * won't be backed by
						   * file. */
						  flags | MAP_ANONYMOUS);

	/* XXX any file consistency checks we need to do? */

	/* Restore the map region we copied. */
	set_child_data(t);

	return mapped_addr;
}

static void* finish_direct_mmap(struct task* t,
				struct current_state_buffer* state,
				struct trace_frame* trace,
				int prot, int flags,
				const struct mmapped_file* file)
{
	struct user_regs_struct* rec_regs = &trace->recorded_regs;
	void* rec_addr = (void*)rec_regs->eax;
	size_t length = rec_regs->ecx;
	off_t offset = rec_regs->ebp;
	struct stat metadata;
	int fd;
	void* mapped_addr;

	if (stat(file->filename, &metadata)) {
		fatal("Failed to stat %s: replay is impossible",
		      file->filename);
	}
	if (metadata.st_ino != file->stat.st_ino
	    || metadata.st_mode != file->stat.st_mode
	    || metadata.st_uid != file->stat.st_uid
	    || metadata.st_gid != file->stat.st_gid
	    || metadata.st_size != file->stat.st_size
	    || metadata.st_mtime != file->stat.st_mtime
	    || metadata.st_ctime != file->stat.st_ctime) {
		log_warn("Metadata of %s changed: replay divergence likely, but continuing anyway ...",
			 file->filename);
	}
	if (should_copy_mmap_region(file->filename, &metadata, prot, flags,
				    WARN_DEFAULT)) {
		log_warn("%s wasn't copied during recording, but now it should be?",
			 file->filename);
	}
	/* Open in the tracee the file that was mapped during
	 * recording. */
	{
		struct restore_mem restore;
		void* child_str = push_tmp_str(t, state, file->filename,
					       &restore);
		/* We only need RDWR for shared writeable mappings.
		 * Private mappings will happily COW from the mapped
		 * RDONLY file.
		 *
		 * TODO: should never map any files writable */
		int oflags = (MAP_SHARED & flags) && (PROT_WRITE & prot) ?
			     O_RDWR : O_RDONLY;
		/* TODO: unclear if O_NOATIME is relevant for mmaps */
		fd = remote_syscall2(t, state, SYS_open, child_str, oflags);
		if (0 > fd) {
			fatal("Couldn't open %s to mmap in tracee",
			      file->filename);
		}
		pop_tmp_mem(t, state, &restore);
	}
	/* And mmap that file. */
	mapped_addr = (void*)
		      remote_syscall6(t, state, SYS_mmap2,
				      rec_addr, length,
				      /* (We let SHARED|WRITEABLE
				       * mappings go through while
				       * they're not handled properly,
				       * but we shouldn't do that.) */
				      prot, flags,
				      fd, offset);
	/* Don't leak the tmp fd.  The mmap doesn't need the fd to
	 * stay open. */
	remote_syscall1(t, state, SYS_close, fd);

	return mapped_addr;
}

static void process_mmap2(struct task* t,
			  struct trace_frame* trace, int exec_state,
			  struct rep_trace_step* step)
{
	int prot = trace->recorded_regs.edx;
	int flags = trace->recorded_regs.esi;
	struct current_state_buffer state;
	void* mapped_addr;

	if (STATE_SYSCALL_ENTRY == exec_state) {
		/* We emulate entry for all types of mmap calls,
		 * successful and not. */
		step->action = TSTEP_ENTER_SYSCALL;
		step->syscall.emu = 1;
		return;
	}
	if (SYSCALL_FAILED(trace->recorded_regs.eax)) {
		/* Failed maps are fully emulated too; nothing
		 * interesting to do. */
		step->action = TSTEP_EXIT_SYSCALL;
		step->syscall.emu = 1;
		step->syscall.emu_ret = 1;
		return;
	}
	/* Successful mmap calls are much more interesting to process.
	 * First we advance to the emulated syscall exit. */
	finish_syscall_emu(t);
	/* Next we hand off actual execution of the mapping to the
	 * appropriate helper. */
	prepare_remote_syscalls(t, &state);
	if (flags & MAP_ANONYMOUS) {
		mapped_addr = finish_anonymous_mmap(t, &state, trace,
						    prot, flags);
	} else {
		struct mmapped_file file;
		read_next_mmapped_file_stats(&file);
		assert(file.time == trace->global_time);
		mapped_addr = file.copied ?
			      finish_copied_mmap(t, &state, trace,
						 prot, flags, &file) :
			      finish_direct_mmap(t, &state, trace,
						 prot, flags, &file);
	}
	/* Finally, we finish by emulating the return value. */
	state.regs.eax = (uintptr_t)mapped_addr;
	finish_remote_syscalls(t, &state);

	validate_args(SYS_mmap2, exec_state, t);

	step->action = TSTEP_RETIRE;
}

/**
 * Return nonzero if this socketcall was "regular" and |step| was
 * updated appropriately, or zero if this was an irregular socketcall
 * that needs to be processed specially.
 */
static int process_socketcall(struct task* t, int state,
			      struct rep_trace_step* step)
{
	int call;

	step->syscall.emu = 1;
	step->syscall.emu_ret = 1;

	if (state == STATE_SYSCALL_ENTRY) {
		step->action = TSTEP_ENTER_SYSCALL;
		return 1;
	}

	step->action = TSTEP_EXIT_SYSCALL;
	switch ((call = read_child_ebx(t->tid))) {
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
		step->syscall.num_emu_args = 0;
		return 1;
	case SYS_GETPEERNAME:
	case SYS_GETSOCKNAME:
		step->syscall.num_emu_args = 2;
		return 1;
	case SYS_RECV:
		step->syscall.num_emu_args = 1;
		return 1;

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
		step->syscall.num_emu_args = 2;
		return 1;

	case SYS_SOCKETPAIR:
	case SYS_GETSOCKOPT:
		step->syscall.num_emu_args = 1;
		return 1;

	case SYS_RECVFROM:
		step->syscall.num_emu_args = 3;
		return 1;

	default:
		return 0;
	}
}

static void process_irregular_socketcall_exit(struct task* t,
					      const struct user_regs_struct* rec_regs)
{
	int call;
	void * base_addr;

	call = rec_regs->ebx;
	base_addr = (void*)rec_regs->ecx;

	switch (call) {
	/* ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags); */
	case SYS_RECVMSG: {
		struct recvmsg_args* args =
			read_child_data(t, sizeof(*args), base_addr);
		
		restore_struct_msghdr(t, args->msg);
		exit_syscall_emu_ret(t, SYS_socketcall);

		sys_free((void**) &args);
		return;
	}
	default:
		fatal("Unknown socketcall %d\n", call);
	}
}

static void process_init_buffers(struct task* t, int exec_state,
				 struct rep_trace_step* step)
{
	void* rec_child_map_addr;
	void* child_map_addr;

	/* This was a phony syscall to begin with. */
	step->syscall.emu = 1;
	step->syscall.emu_ret = 1;

	if (STATE_SYSCALL_ENTRY == exec_state) {
		step->action = TSTEP_ENTER_SYSCALL;
		return;
	}

	step->action = TSTEP_RETIRE;

	/* Proceed to syscall exit so we can run our own syscalls. */
	exit_syscall_emu(t, SYS_rrcall_init_buffers, 0);
	rec_child_map_addr = (void*)t->trace.recorded_regs.eax;

	/* We don't want the desched event fd during replay, because
	 * we already know where they were.  (The perf_event fd is
	 * emulated anyway.) */
	child_map_addr = init_buffers(t, rec_child_map_addr,
				      DONT_SHARE_DESCHED_EVENT_FD);

	assert_exec(t, child_map_addr == rec_child_map_addr,
		    "Should have mapped syscallbuf at %p, but it's at %p",
		    rec_child_map_addr, child_map_addr);
}

static void process_restart_syscall(struct task* t, int syscallno)
{
	switch (syscallno) {
	case SYS_nanosleep:
		/* Write the remaining-time outparam that we were
		 * forced to during recording. */
		set_child_data(t);

	default:
		return;
	}
}

void rep_process_syscall(struct task* t, struct rep_trace_step* step)
{
	int syscall = t->trace.stop_reason; /* FIXME: don't shadow syscall() */
	const struct syscall_def* def = &syscall_table[syscall];
	pid_t tid = t->tid;
	struct trace_frame* trace = &(t->trace);
	int state = trace->state;
	const struct user_regs_struct* rec_regs = &trace->recorded_regs;

	if (STATE_SYSCALL_EXIT == state
	    && SYSCALL_MAY_RESTART(rec_regs->eax)) {
		/* During recording, when a syscall exits with a
		 * restart "error", the kernel may use some black
		 * magic to restart that syscall without intervention
		 * from userspace.  rr can observe that magic with
		 * ptrace, but there's no way to directly replicate it
		 * with a syscall exit/re-enter pair of commands.
		 *
		 * So instead we leave the syscall return "hanging".
		 * If it's restarted, we'll skip advancing to the
		 * restart entry below and just emulate exit by
		 * setting the kernel outparams. */
		set_return_value(t);
		process_restart_syscall(t, syscall);
		/* Use this record to recognize the syscall if it
		 * indeed restarts. */
		push_syscall_interruption(t, rec_regs->orig_eax, rec_regs);
		step->action = TSTEP_RETIRE;
		debug("  %s interrupted, may restart", syscallname(syscall));
		return;
	}

	if (EV_SYSCALL_INTERRUPTION == t->ev->type) {
		int restarting;

		assert_exec(t, STATE_SYSCALL_ENTRY == state,
			    "Syscall interruptions can only be seen at syscall (re-)entry");

		restarting = is_syscall_restart(t, syscall, rec_regs);
		pop_syscall_interruption(t);
		if (restarting) {
			/* This "emulates" the restart by just
			 * continuing on from the interrupted
			 * syscall. */
			step->action = TSTEP_RETIRE;
			return;
		}
	}
	assert_exec(t, SYS_restart_syscall != syscall,
		    "restart_syscall must have interruption record");

	assert_exec(t, syscall < ALEN(syscall_table),
		    "%d not in syscall table, but possibly valid", syscall);
	assert_exec(t, rep_UNDEFINED != def->type,
		    "Valid but unhandled syscallno %d", syscall);

	step->syscall.no = syscall;

	if (rep_IRREGULAR != def->type) {
		step->syscall.num_emu_args = def->num_emu_args;
		step->action = STATE_SYSCALL_ENTRY == state ?
			       TSTEP_ENTER_SYSCALL : TSTEP_EXIT_SYSCALL;
		step->syscall.emu = rep_EMU == def->type;
		step->syscall.emu_ret =
			rep_EMU == def->type || rep_EXEC_RET_EMU == def->type;
		return;
	}

	assert(rep_IRREGULAR == def->type);

	/* Manual implementations of irregular syscalls. */

	switch (syscall) {
	case SYS_exit:
	case SYS_exit_group:
		step->syscall.emu = 0;
		assert(state == STATE_SYSCALL_ENTRY);
		step->action = TSTEP_ENTER_SYSCALL;
		return;

	case SYS_fcntl64:
		step->syscall.emu = 1;
		step->syscall.emu_ret = 1;
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
			case F_SETOWN_EX:
			case F_SETSIG:
				step->syscall.num_emu_args = 0;
				break;
			case F_SETLK:
			case F_SETLK64:
			case F_SETLKW:
			case F_SETLKW64:
			case F_GETLK:
			case F_GETLK64:
				step->syscall.num_emu_args = 1;
				break;
			default:
				fatal("Unknown fcntl64 command: %d", cmd);
			}
		}
		return;

	case SYS_futex:
		step->syscall.emu = 1;
		step->syscall.emu_ret = 1;
		if (state == STATE_SYSCALL_ENTRY) {
			step->action = TSTEP_ENTER_SYSCALL;
		} else {
			int op = read_child_ecx(tid) & FUTEX_CMD_MASK;

			step->action = TSTEP_EXIT_SYSCALL;
			switch (op) {
			case FUTEX_WAKE:
			case FUTEX_WAIT_BITSET:
			case FUTEX_WAIT:
			case FUTEX_LOCK_PI:
			case FUTEX_UNLOCK_PI:
				step->syscall.num_emu_args = 1;
				break;
			case FUTEX_CMP_REQUEUE:
			case FUTEX_WAKE_OP:
			case FUTEX_CMP_REQUEUE_PI:
			case FUTEX_WAIT_REQUEUE_PI:
				step->syscall.num_emu_args = 2;
				break;
			default:
				fatal("Unknown futex op %d", op);
			}
		}
		return;

	case SYS_ioctl:
		return process_ioctl(t, state, step);

	case SYS_mmap2:
		return process_mmap2(t, trace, state, step);

	case SYS_nanosleep:
		step->syscall.emu = 1;
		step->syscall.emu_ret = 1;
		if (STATE_SYSCALL_ENTRY == state) {
			step->action = TSTEP_ENTER_SYSCALL;
		} else {
			step->action = TSTEP_EXIT_SYSCALL;
			step->syscall.num_emu_args =
				(trace->recorded_regs.ecx != 0) ? 1 : 0;
		}
		return;

	case SYS_quotactl:
		step->syscall.emu = 1;
		step->syscall.emu_ret = 1;
		if (state == STATE_SYSCALL_ENTRY) {
			step->action = TSTEP_ENTER_SYSCALL;
		} else {
			int cmd = read_child_ebp(t->tid);

			step->action = TSTEP_EXIT_SYSCALL;
			switch (cmd & SUBCMDMASK) {
			case Q_GETQUOTA:
			case Q_GETINFO:
			case Q_GETFMT:
				step->syscall.num_emu_args = 1;
				break;
			default:
				step->syscall.num_emu_args = 0;
			}
		}
		return;

	case SYS_read:
		step->syscall.emu = 1;
		step->syscall.emu_ret = 1;
		if (STATE_SYSCALL_ENTRY == state) {
			step->action = TSTEP_ENTER_SYSCALL;
		} else {
			step->action = TSTEP_EXIT_SYSCALL;
			step->syscall.num_emu_args = 1;
		}
		return;

	case SYS_socketcall:
		if (process_socketcall(t, state, step)) {
			return;
		}
		break;

	case SYS_write:
		step->syscall.num_emu_args = 0;
		step->syscall.emu = 1;
		step->syscall.emu_ret = 1;
		if (state == STATE_SYSCALL_ENTRY) {
			step->action = TSTEP_ENTER_SYSCALL;
			return;
		}

		step->action = TSTEP_EXIT_SYSCALL;
		/* XXX technically this will print the output before
		 * we reach the interrupt.  That could maybe cause
		 * issues in the future. */
		rep_maybe_replay_stdio_write(t);
		/* write() can be desched'd, but it doesn't use
		 * scratch, so we might have saved 0 bytes of scratch
		 * after a desched. */
		maybe_noop_restore_syscallbuf_scratch(t);
		return;

	case SYS_rrcall_init_buffers:
		return process_init_buffers(t, state, step);

	default:
		break;
	}

	/* TODO: irregular syscalls that don't understand
	 * trace_step */
	step->action = TSTEP_RETIRE;

	switch (syscall) {

	case SYS_clone:
		process_clone(t, trace, state);
		break;

	case SYS_execve: {
		int check;

		if (state == STATE_SYSCALL_ENTRY) {
			enter_syscall_exec(t, syscall);
			break;
		}
		if (0 > rec_regs->eax) {
			/* Failed exec(). */
			exit_syscall_exec(t, syscall, 0, DONT_EMULATE_RETURN);
			read_child_registers(tid, &t->regs);
			assert_exec(t, rec_regs->eax == t->regs.eax,
				    "Recorded exec() return %ld, but replayed %ld",
				    rec_regs->eax, t->regs.eax);
			break;
		}

		/* we need an additional ptrace syscall, since ptrace
		 * is setup with PTRACE_O_TRACEEXEC */
		__ptrace_cont(t);
		read_child_registers(tid, &t->regs);

		/* We just saw a successful exec(), so from now on we
		 * know that the address space layout for the replay
		 * tasks will (should!) be the same as for the
		 * recorded tasks.  So we can start validating
		 * registers at events. */
		validate = TRUE;

		check = t->regs.ebx;
		/* if the execve comes from a vfork system call the
		 * ebx register is not zero. in this case, no recorded
		 * data needs to be injected */
		if (check == 0) {
			size_t size;
			void* rec_addr;
			void* data = read_raw_data(&(t->trace),
						   &size, &rec_addr);
			if (data != NULL ) {
				write_child_data(t, size, (void*)rec_addr,
						 data);
				sys_free((void**) &data);
			}
		}

		init_scratch_memory(t);

		set_return_value(t);
		validate_args(syscall, state, t);
		break;
	}
	case SYS_ipc:
		process_ipc(t, trace, state);
		break;

	case SYS_mremap:
		if (state == STATE_SYSCALL_ENTRY) {
			enter_syscall_exec(t, syscall);
		} else {
			/* By using a fixed address remapping we can
			 * be sure that the mappings remain identical
			 * in the record and replay/
			 */
			struct user_regs_struct orig_regs;
			read_child_registers(t->tid, &orig_regs);

			struct user_regs_struct tmp_regs;
			memcpy(&tmp_regs, &orig_regs, sizeof(tmp_regs));
			/* set mapping to fixed and initialize the new
			 * address with the recorded address
			 */

			/* is hack is necessary, since mremap does not
			 * like the FIXED flag if source and
			 * destination address are the same */
			if (orig_regs.ebx != t->trace.recorded_regs.eax) {
				tmp_regs.esi |= MREMAP_FIXED;
				tmp_regs.edi = t->trace.recorded_regs.eax;
			}

			write_child_registers(t->tid, &tmp_regs);

			__ptrace_cont(t);
			/* obtain the new address and reset to the old
			 * register values */
			read_child_registers(t->tid, &tmp_regs);

			orig_regs.eax = tmp_regs.eax;
			write_child_registers(t->tid, &orig_regs);
			validate_args(syscall, state, t);
		}

	case SYS_recvmmsg: {
		struct mmsghdr* msg = (void*)rec_regs->ecx;
		ssize_t nmmsgs = rec_regs->eax;
		int i;

		if (state == STATE_SYSCALL_ENTRY) {
			return enter_syscall_emu(t, syscall);
		}

		for (i = 0; i < nmmsgs; ++i, ++msg) {
			restore_struct_mmsghdr(t, msg);
		}
		return exit_syscall_emu_ret(t, syscall);
	}

	case SYS_sendmmsg: {
		ssize_t nmmsgs = rec_regs->eax;
		int i;

		if (state == STATE_SYSCALL_ENTRY) {
			return enter_syscall_emu(t, syscall);
		}

		for (i = 0; i < nmmsgs; ++i) {
			set_child_data(t);
		}
		return exit_syscall_emu_ret(t, syscall);
	}

	case SYS_setpgid:
		if (state == STATE_SYSCALL_ENTRY) {
			enter_syscall_emu(t, SYS_setpgid);
		} else {
			write_child_ebx(t->tid,
					t->trace.recorded_regs.ebx);
			exit_syscall_emu(t, SYS_setpgid, 0);
		}
		break;

	case SYS_sigreturn:
	case SYS_rt_sigreturn:
		if (state == STATE_SYSCALL_ENTRY) {
			enter_syscall_emu(t, syscall);
			finish_syscall_emu(t);
		} else {
			write_child_main_registers(t->tid,
						   &trace->recorded_regs);
		}
		break;

	case SYS_socketcall:
		assert(STATE_SYSCALL_EXIT == state);
		return process_irregular_socketcall_exit(t, rec_regs);

	case SYS_vfork:
		if (state == STATE_SYSCALL_ENTRY) {
			/* go to the system call */
			__ptrace_cont(t);
			if (PTRACE_EVENT_VFORK ==
			    GET_PTRACE_EVENT(t->status)) {
				unsigned long new_tid = sys_ptrace_getmsg(tid);
				/* wait until the new thread is ready */
				int status;
				sys_waitpid(new_tid, &status);

				struct trace_frame next_trace;
				peek_next_trace(&next_trace);
				rep_sched_register_thread(new_tid,
							  next_trace.tid);
			}
			validate_args(syscall, state, t);
		} else {
			exit_syscall_exec(t, syscall, 0, EMULATE_RETURN);
		}
		break;

	default:
		fatal("Unhandled  irregular syscall %d", syscall);
	}
}
