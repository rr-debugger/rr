/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

//#define DEBUGTAG "ProcessSyscallRec"

#include "rec_process_event.h"

#define _GNU_SOURCE

#include <asm/ldt.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <linux/net.h>
#include <linux/sem.h>
#include <linux/shm.h>
#include <linux/prctl.h>
#include <poll.h>
#include <sched.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/quota.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/utsname.h>
#include <sys/vfs.h>

#include "handle_ioctl.h"

#include "../share/dbg.h"
#include "../share/ipc.h"
#include "../share/sys.h"
#include "../share/syscall_buffer.h"
#include "../share/task.h"
#include "../share/trace.h"
#include "../share/util.h"

/**
 *   static void read_socketcall_args(struct task* t,
 *                                    const struct user_regs_struct* regs,
 *                                    long** argsp, long[n] args);
 *
 * Read the socketcall args pushed by |t| as part of the syscall in
 * |regs| into the |args| outparam.  Also store the address of the
 * socketcall args into |*argsp|.
 *
 * NB: this is a macro to enable it to "infer" the size of |args|.
 * This of course wouldn't be necessary with C++.
 */
#define READ_SOCKETCALL_ARGS(_t, _regs, _argsp, _args)			\
	do {								\
		long* _tmp;						\
		*_argsp = (void*)(_regs)->ecx;				\
		_tmp = read_child_data(_t, sizeof(_args), *_argsp);	\
		memcpy(_args, _tmp, sizeof(_args));			\
		sys_free((void**)&_tmp);				\
	} while(0)


/**
 * Erase any scratch pointer initialization done for |t| and leave
 * the state bits ready to be initialized again.
 */
static void reset_scratch_pointers(struct task* t)
{
	assert(t->ev->type == EV_SYSCALL);

	FIXEDSTACK_CLEAR(&t->ev->syscall.saved_args);
	t->ev->syscall.tmp_data_ptr = t->scratch_ptr;
	t->ev->syscall.tmp_data_num_bytes = -1;
}

/**
 * Record a tracee argument pointer that (most likely) was replaced by
 * a pointer into scratch memory.  |argp| can have any value,
 * including NULL.  It must be fetched by calling |pop_arg_ptr()|
 * during processing syscall results, and in reverse order of calls to
 * |push*()|.
 */
static void push_arg_ptr(struct task* t, void* argp)
{
	FIXEDSTACK_PUSH(&t->ev->syscall.saved_args, argp);
}

/**
 * Reset scratch state for |t|, because scratch can't be used for
 * |event|.  Log a warning as well.
 */
static int abort_scratch(struct task* t, const char* event)
{
	int num_bytes = t->ev->syscall.tmp_data_num_bytes;

	assert(t->ev->syscall.tmp_data_ptr == t->scratch_ptr);

	if (0 > num_bytes) {
		log_warn("`%s' requires scratch buffers, but that's not implemented.  Disabling context switching: deadlock may follow.",
			 event);
	} else {
		log_warn("`%s' needed a scratch buffer of size %d, but only %d was available.  Disabling context switching: deadlock may follow.",
			 event, num_bytes, t->scratch_size);
	}
	reset_scratch_pointers(t);
	return 0;		/* don't allow context-switching */
}

/**
 * Return nonzero if the scratch state initialized for |t| fits
 * within the allocated region (and didn't overflow), zero otherwise.
 */
static int can_use_scratch(struct task* t, void* scratch_end)
{
	void* scratch_start = t->scratch_ptr;

	assert(t->ev->syscall.tmp_data_ptr == t->scratch_ptr);

	t->ev->syscall.tmp_data_num_bytes = (scratch_end - scratch_start);
	return (0 <= t->ev->syscall.tmp_data_num_bytes
		&& t->ev->syscall.tmp_data_num_bytes <= t->scratch_size);
}

/**
 * Initialize any necessary state to execute the socketcall that |t|
 * is stopped at, for example replacing tracee args with pointers into
 * scratch memory if necessary.
 */
int prepare_socketcall(struct task* t, int would_need_scratch,
		       struct user_regs_struct* regs)
{
	pid_t tid = t->tid;
	void* scratch = would_need_scratch ?
			t->ev->syscall.tmp_data_ptr : NULL;
	long* argsp;
	void* tmpargsp;

	assert(!task_desched_rec(t));

	/* int socketcall(int call, unsigned long *args) {
	 * 		long a[6];
	 * 		copy_from_user(a,args);
	 *  	sys_recv(a0, (void __user *)a1, a[2], a[3]);
	 *  }
	 *
	 *  (from http://lxr.linux.no/#linux+v3.6.3/net/socket.c#L2354)
	 */
	switch (regs->ebx) {
	/* ssize_t recv([int sockfd, void *buf, size_t len, int flags]) */
	case SYS_RECV: {
		long args[4];

		if (!would_need_scratch) {
			return 1;
		}
		READ_SOCKETCALL_ARGS(t, regs, &argsp, args);
		/* The socketcall args are passed on the stack and
		 * pointed at by $ecx.  We need to set up scratch
		 * buffer space for |buf|, but we also have to
		 * overwrite that pointer in the socketcall args on
		 * the stack.  So what we do is copy the socketcall
		 * args to our scratch space, replace the |buf| arg
		 * there with a pointer to the scratch region just
		 * /after/ the socketcall args, and then hand the
		 * scratch pointer to the kernel. */
		/* The socketcall arg pointer. */
		push_arg_ptr(t, argsp);
		regs->ecx = (uintptr_t)(tmpargsp = scratch);
		scratch += sizeof(args);
		/* The |buf| pointer. */
		push_arg_ptr(t, (void*)args[1]);
		args[1] = (uintptr_t)scratch;
		scratch += args[2]/*len*/;
		if (!can_use_scratch(t, scratch)) {
			return abort_scratch(t, "recv");
		}

		write_child_data(t, sizeof(args), tmpargsp, args);
		write_child_registers(tid, regs);
		return 1;
	}

	/* int accept([int sockfd, struct sockaddr *addr, socklen_t *addrlen]) */
	/* int accept4([int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags]) */
	case SYS_ACCEPT:
	case SYS_ACCEPT4: {
		long args[4];
		socklen_t* addrlenp;
		socklen_t addrlen;

		if (!would_need_scratch) {
			return 1;
		}
		READ_SOCKETCALL_ARGS(t, regs, &argsp, args);
		addrlenp = (void*)args[2];
		assert(sizeof(long) == sizeof(addrlen));
		addrlen = read_child_data_word(tid, addrlenp);
		/* We use the same basic scheme here as for RECV
		 * above.  For accept() though, there are two
		 * (in)outparams: |addr| and |addrlen|.  |*addrlen| is
		 * the total size of |addr|, so we reserve that much
		 * space for it.  |*addrlen| is set to the size of the
		 * returned sockaddr, so we reserve space for
		 * |addrlen| too. */
		/* The socketcall arg pointer. */
		push_arg_ptr(t, argsp);
		regs->ecx = (uintptr_t)(tmpargsp = scratch);
		scratch += sizeof(args);
		/* The |addrlen| pointer. */
		push_arg_ptr(t, addrlenp);
		args[2] = (uintptr_t)scratch;
		scratch += sizeof(*addrlenp);
		/* The |addr| pointer. */
		push_arg_ptr(t, (void*)args[1]);
		args[1] = (uintptr_t)scratch;
		scratch += addrlen;

		if (!can_use_scratch(t, scratch)) {
			return abort_scratch(t, "accept");
		}

		write_child_data(t, sizeof(args), tmpargsp, args);
		write_child_registers(tid, regs);
		return 1;
	}

	case SYS_RECVFROM:
		/* TODO: this can block, needs scratch. */
		return abort_scratch(t, "recvfrom");

	case SYS_RECVMSG:
		/* TODO: this can block too, so also needs scratch
		 * pointers.  Unfortunately the format is fiendishly
		 * complicated, so setting up scratch is rather
		 * nontrivial :(. */
		return abort_scratch(t, "recvmsg");

	default:
		return 0;
	}
}

/**
 * |t| was descheduled while in a buffered syscall.  We don't want
 * to use scratch memory for the call, because the syscallbuf itself
 * is serving that purpose.  More importantly, we *can't* set up
 * scratch for |t|, because it's already in the syscall.  So this
 * function sets things up so that the *syscallbuf* memory that |t|
 * is using as ~scratch will be recorded, so that it can be replayed.
 */
static int set_up_scratch_for_syscallbuf(struct task* t, int syscallno)
{
	const struct syscallbuf_record* rec = task_desched_rec(t);

	assert(task_desched_rec(t));
	assert_exec(t, syscallno == rec->syscallno, 
		    "Syscallbuf records syscall %s, but expecting %s",
		    syscallname(rec->syscallno), syscallname(syscallno));

	reset_scratch_pointers(t);
	t->ev->syscall.tmp_data_ptr =
		t->syscallbuf_child +
		(rec->extra_data - (byte*)t->syscallbuf_hdr);
	/* |rec->size| is the entire record including extra data; we
	 * just care about the extra data here. */
	t->ev->syscall.tmp_data_num_bytes = rec->size - sizeof(*rec);
	return 1;
}

int rec_prepare_syscall(struct task* t)
{
	pid_t tid = t->tid;
	int syscallno = t->ev->syscall.no;
	/* If we are called again due to a restart_syscall, we musn't
	 * redirect to scratch again as we will lose the original
	 * addresses values. */
	bool restart = (syscallno == SYS_restart_syscall);
	struct user_regs_struct regs;
	int would_need_scratch;
	void* scratch = NULL;

	if (task_desched_rec(t)) {
		return set_up_scratch_for_syscallbuf(t, syscallno);
	}

	read_child_registers(t->tid, &regs);

	/* For syscall params that may need scratch memory, they
	 * *will* need scratch memory if |would_need_scratch| is
	 * nonzero.  They *don't* need scratch memory if we're
	 * restarting a syscall, since if that's the case we've
	 * already set it up. */
	would_need_scratch = !restart;
	if (would_need_scratch) {
		/* Don't stomp scratch pointers that were set up for
		 * the restarted syscall.
		 *
		 * TODO: but, we'll stomp if we reenter through a
		 * signal handler ... */
		reset_scratch_pointers(t);
		scratch = t->ev->syscall.tmp_data_ptr;
	}

	switch (syscallno) {
	case SYS_splice:
		return 1;

	/* int futex(int *uaddr, int op, int val, const struct timespec *timeout, int *uaddr2, int val3); */
	case SYS_futex:
		switch (regs.ecx & FUTEX_CMD_MASK) {
		case FUTEX_LOCK_PI:
		case FUTEX_LOCK_PI_PRIVATE:
		case FUTEX_WAIT:
		case FUTEX_WAIT_PRIVATE:
		case FUTEX_WAIT_BITSET:
		case FUTEX_WAIT_BITSET_PRIVATE:
		case FUTEX_WAIT_REQUEUE_PI:
		case FUTEX_WAIT_REQUEUE_PI_PRIVATE:
			return 1;
		default:
			return 0;
		}

	case SYS_socketcall:
		return prepare_socketcall(t, would_need_scratch, &regs);

	case SYS__newselect:
		return 1;

	/* ssize_t read(int fd, void *buf, size_t count); */
	case SYS_read: {
		if (!would_need_scratch) {
			return 1;
		}
		push_arg_ptr(t, (void*)regs.ecx);
		regs.ecx = (uintptr_t)scratch;
		scratch += regs.edx/*count*/;

		if (!can_use_scratch(t, scratch)) {
			return abort_scratch(t, syscallname(syscallno));
		}

		write_child_registers(tid, &regs);
		return 1;
	}

	case SYS_write:
		return 1;

	/* pid_t waitpid(pid_t pid, int *status, int options); */
	/* pid_t wait4(pid_t pid, int *status, int options, struct rusage *rusage); */
	case SYS_waitpid:
	case SYS_wait4: {
		int* status = (int*)regs.ecx;
		struct rusage* rusage = (SYS_wait4 == syscallno) ?
					(struct rusage*)regs.esi : NULL;

		if (!would_need_scratch) {
			return 1;
		}
		push_arg_ptr(t, status);
		if (status) {
			regs.ecx = (uintptr_t)scratch;
			scratch += sizeof(*status);
		}
		push_arg_ptr(t, rusage);
		if (rusage) {
			regs.esi = (uintptr_t)scratch;
			scratch += sizeof(*rusage);
		}

		if (!can_use_scratch(t, scratch)) {
			return abort_scratch(t, syscallname(syscallno));
		}

		write_child_registers(tid, &regs);
		return 1;
	}

	/* int poll(struct pollfd *fds, nfds_t nfds, int timeout) */
	/* int ppoll(struct pollfd *fds, nfds_t nfds,
	 *           const struct timespec *timeout_ts,
	 *           const sigset_t *sigmask); */
	case SYS_poll:
	case SYS_ppoll: {
		struct pollfd* fds = (struct pollfd*)regs.ebx;
		struct pollfd* fds2 = scratch;
		nfds_t nfds = regs.ecx;

		if (!would_need_scratch) {
			return 1;
		}
		/* XXX fds can be NULL, right? */
		push_arg_ptr(t, fds);
		regs.ebx = (uintptr_t)fds2;
		scratch += nfds * sizeof(*fds);

		if (!can_use_scratch(t, scratch)) {
			return abort_scratch(t, syscallname(syscallno));
		}
		/* |fds| is an inout param, so we need to copy over
		 * the source data. */
		memcpy_child(t, fds2, fds, nfds * sizeof(*fds));
		write_child_registers(tid, &regs);
		return 1;
	}

	/* int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5); */
	case SYS_prctl:
		/* TODO: many of these prctls are not blocking. */
		if (!would_need_scratch) {
			return 1;
		}
		switch (regs.ebx) {
		case PR_GET_ENDIAN:
		case PR_GET_FPEMU:
		case PR_GET_FPEXC:
		case PR_GET_PDEATHSIG:
		case PR_GET_TSC:
		case PR_GET_UNALIGN: {
			int* outparam = (void*)regs.ecx;

			push_arg_ptr(t, outparam);
			regs.ecx = (uintptr_t)scratch;
			scratch += sizeof(*outparam);

			if (!can_use_scratch(t, scratch)) {
				return abort_scratch(t,
						     syscallname(syscallno));
			}

			write_child_registers(tid, &regs);
			return 1;
		}
		case PR_GET_NAME: {
			/* Outparam is a |char*| in the second
			 * parameter.  Thus sayeth the docs:
			 *
			 *   The buffer should allow space for up to
			 *   16 bytes; The returned string will be
			 *   null-terminated if it is shorter than
			 *   that. */
			char* name = (void*)regs.ecx;

			push_arg_ptr(t, name);
			regs.ecx = (uintptr_t)scratch;
			scratch += 16;

			if (!can_use_scratch(t, scratch)) {
				return abort_scratch(t,
						     syscallname(syscallno));
			}

			write_child_registers(tid, &regs);
			return 1;
		}
		default:
			/* TODO: there are many more prctls with
			 * outparams ... */
			return 1;
		}

	/* int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout); */
	case SYS_epoll_wait: {
		struct epoll_event* events = (struct epoll_event*)regs.ecx;
		int maxevents = regs.edx;

		if (!would_need_scratch) {
			return 1;
		}
		push_arg_ptr(t, events);
		regs.ecx = (uintptr_t)scratch;
		scratch += maxevents * sizeof(*events);

		if (!can_use_scratch(t, scratch)) {
			return abort_scratch(t, syscallname(syscallno));
		}

		/* (Unlike poll(), the |events| param is a pure
		 * outparam, no copy-over needed.) */
		write_child_registers(tid, &regs);
		return 1;
	}

	case SYS_epoll_pwait:
		fatal("Unhandled syscall %s", strevent(syscallno));
		return 1;

	/* The following two syscalls enable context switching not for
	 * liveness/correctness reasons, but rather because if we
	 * didn't context-switch away, rr might end up busy-waiting
	 * needlessly.  In addition, albeit far less likely, the
	 * client program may have carefully optimized its own context
	 * switching and we should take the hint. */

	/* int nanosleep(const struct timespec *req, struct timespec *rem); */
	case SYS_nanosleep: {
		struct timespec* rem = (void*)regs.ecx;

		if (!would_need_scratch) {
			return 1;
		}
		push_arg_ptr(t, rem);
		if (rem) {
       			regs.ecx = (uintptr_t)scratch;
			scratch += sizeof(*rem);
		}

		if (!can_use_scratch(t, scratch)) {
			return abort_scratch(t, syscallname(syscallno));
		}

		write_child_registers(t->tid, &regs);
		return 1;
	}

	case SYS_sched_yield:
		return 1;

	default:
		return 0;
	}
}

/**
 * Write a trace data record that when replayed will be a no-op.  This
 * is used to avoid having special cases in replay code for failed
 * syscalls, e.g.
 */
static void record_noop_data(struct task* t)
{
	record_parent_data(t, 0, NULL, NULL);
}

void rec_prepare_restart_syscall(struct task* t)
{
	int syscallno = t->ev->syscall.no;
	switch (syscallno) {
	case SYS_nanosleep: {
		/* Hopefully uniquely among syscalls, nanosleep()
		 * requires writing to its remaining-time outparam
		 * *only if* the syscall fails with -EINTR.  When a
		 * nanosleep() is interrupted by a signal, we don't
		 * know a priori whether it's going to be eventually
		 * restarted or not.  (Not easily, anyway.)  So we
		 * don't know whether it will eventually return -EINTR
		 * and would need the outparam written.  To resolve
		 * that, we do what the kernel does, and update the
		 * outparam at the -ERESTART_RESTART interruption
		 * regardless. */
		struct timespec* rem =
			*FIXEDSTACK_TOP(&t->ev->syscall.saved_args);
		struct timespec* rem2 = (void*)t->regs.ecx;

		if (rem) {
			memcpy_child(t, rem, rem2, sizeof(*rem));
			record_child_data(t, sizeof(*rem), rem);
		} else {
			record_noop_data(t);
		}
		/* If the nanosleep does indeed restart, then we'll
		 * write the outparam twice.  *yawn*. */
		return;
	}
	default:
		return;
	}
}

/**
 * Read the scratch data written by the kernel in the syscall and
 * return an opaque handle to it.  The outparam |iter| can be used to
 * copy the read memory.
 *
 * The returned opaque handle must be passed to
 * |finish_restoring_scratch()|.
 */
static void* start_restoring_scratch(struct task* t, void** iter)
{
	void* scratch = t->ev->syscall.tmp_data_ptr;
	ssize_t num_bytes = t->ev->syscall.tmp_data_num_bytes;

	assert(num_bytes >= 0);

	*iter = read_child_data(t, num_bytes, scratch);
	return *iter;
}

/**
 * Return nonzero if tracee pointers were saved while preparing for
 * the syscall |t->ev|.
 */
static int has_saved_arg_ptrs(struct task* t)
{
	return !FIXEDSTACK_EMPTY(&t->ev->syscall.saved_args);
}

/**
 * Return the replaced tracee argument pointer saved by the matching
 * call to |push_arg_ptr()|.
 */
static void* pop_arg_ptr(struct task* t)
{
	return FIXEDSTACK_POP(&t->ev->syscall.saved_args);
}

/**
 * Write |num_bytes| of data from |parent_data_iter| to |child_addr|.
 * Record the written data so that it can be restored during replay of
 * |syscallno|.
 */
static void restore_and_record_arg_buf(struct task* t,
				       size_t num_bytes, void* child_addr,
				       void** parent_data_iter)
{
	void* parent_data = *parent_data_iter;
	write_child_data(t, num_bytes, child_addr, parent_data);
	record_parent_data(t, num_bytes, child_addr, parent_data);
	*parent_data_iter += num_bytes;
}

/**
 * Finish the sequence of operations begun by the most recent
 * |start_restoring_scratch()| and check that no mistakes were made.
 * |*data| must be the opaque handle returned by |start_*()|.
 *
 * Don't call this directly; use one of the helpers below.
 */
enum { NO_SLACK = 0, ALLOW_SLACK = 1 };
static void finish_restoring_scratch_slack(struct task* t,
					   void* iter, void** data,
					   int slack)
{
	ssize_t consumed = (iter - *data);
	ssize_t diff = t->ev->syscall.tmp_data_num_bytes - consumed;

	assert(t->ev->syscall.tmp_data_ptr == t->scratch_ptr);
	assert_exec(t, !diff || (slack && diff > 0),
		    "Saved %d bytes of scratch memory but consumed %d",
		    t->ev->syscall.tmp_data_num_bytes, consumed);
	if (slack) {
		debug("Left %d bytes unconsumed in scratch", diff);
	}
	assert_exec(t, FIXEDSTACK_EMPTY(&t->ev->syscall.saved_args),
		    "Under-consumed saved arg pointers");

	sys_free(data);
}

/**
 * Like above, but require that all saved scratch data was consumed.
 */
static void finish_restoring_scratch(struct task* t,
				     void* iter, void** data)
{
	return finish_restoring_scratch_slack(t, iter, data, NO_SLACK);
}

/**
 * Like above, but allow some saved scratch data to remain unconsumed,
 * for example if a buffer wasn't filled entirely.
 */
static void finish_restoring_some_scratch(struct task* t,
					  void* iter, void** data)
{
	return finish_restoring_scratch_slack(t, iter, data, ALLOW_SLACK);
}

static void process_socketcall(struct task* t,
			       struct user_regs_struct* call_regs,
			       int call, void* base_addr)
{
	pid_t tid = t->tid;
	struct user_regs_struct regs;

	debug("socket call: %d\n", call);

	/* TODO: use t->regs exclusively */
	memcpy(&regs, call_regs, sizeof(regs));

	switch (call) {
	/* int socket(int domain, int type, int protocol); */
	case SYS_SOCKET:
	/* int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen); */
	case SYS_CONNECT:
	/* int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen); */
	case SYS_BIND:
	/* int listen(int sockfd, int backlog) */
	case SYS_LISTEN:
	/* ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) */
	case SYS_SENDMSG:
	/* ssize_t send(int sockfd, const void *buf, size_t len, int flags) */
	case SYS_SEND:
	/* ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen); */
	case SYS_SENDTO:
	/* int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen); */
	case SYS_SETSOCKOPT:
	/* int shutdown(int socket, int how) */
	case SYS_SHUTDOWN:
		return;

	/* int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen); */
	case SYS_GETPEERNAME:
	/* int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen); */
	case SYS_GETSOCKNAME: {
		void** addr = read_child_data(t, sizeof(void*), base_addr + sizeof(int) + sizeof(struct sockaddr*));
		socklen_t *addrlen = read_child_data(t, sizeof(socklen_t), *addr);
		record_child_data(t, sizeof(socklen_t), *addr);
		sys_free((void**) &addr);

		addr = read_child_data(t, sizeof(void*), base_addr + sizeof(int));
		record_child_data(t, *addrlen, *addr);
		sys_free((void**) &addr);
		sys_free((void**) &addrlen);
		return;
	}

	/* ssize_t recv(int sockfd, void *buf, size_t len, int flags) 
	 * implemented by:
	 * int socketcall(int call, unsigned long *args) {
	 * 		long a[6];
	 * 		copy_from_user(a,args);
	 *  	sys_recv(a0, (void __user *)a1, a[2], a[3]);
	 *  }
	 */
	case SYS_RECV: {
		long args[4];
		void* buf;
		void* argsp;
		void* iter;
		void* data = NULL;
		ssize_t nrecvd;

		nrecvd = regs.eax;
		if (has_saved_arg_ptrs(t)) {
			buf = pop_arg_ptr(t);
			argsp = pop_arg_ptr(t);
			data = start_restoring_scratch(t, &iter);
			/* We don't need to record the fudging of the
			 * socketcall arguments, because we won't
			 * replay that. */
			memcpy(args, iter, sizeof(args));
			iter += sizeof(args);
		} else {
			long* argsp;
			READ_SOCKETCALL_ARGS(t, &regs, &argsp, args);
			buf = (void*)args[1];
		}

		/* Restore |buf| contents. */
		if (0 < nrecvd) {
			if (data) {
				restore_and_record_arg_buf(t, nrecvd, buf,
							   &iter);
			} else {
				record_child_data(t, nrecvd, buf);
			}
		} else {
			record_noop_data(t);
		}

		if (data) {
			/* Restore the pointer to the original args. */
			regs.ecx = (uintptr_t)argsp;
			write_child_registers(tid, &regs);
			finish_restoring_some_scratch(t, iter, &data);
		}
		return;
	}

	/* ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags); */
	case SYS_RECVMSG: {
		struct recvmsg_args* args =
			read_child_data(t, sizeof(*args), base_addr);
		record_struct_msghdr(t, args->msg);

		sys_free((void**) &args);
		return;
	}

	/* ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen); */
	case SYS_RECVFROM: {
		struct recvfrom_args {
			long fd;
			void* buf;
			long len;
			long flags;
			struct sockaddr* src_addr;
			socklen_t* addrlen;
		};
		struct recvfrom_args* child_args;
		int recvdlen = regs.eax;

		child_args = read_child_data(t, sizeof(*child_args),
					     base_addr);

		if (recvdlen > 0) {
			record_child_data(t, child_args->len,
					  child_args->buf);
		} else {
			record_noop_data(t);
		}
		if (child_args->src_addr && child_args->addrlen) {
			long len =
				read_child_data_word(t->tid,
						     child_args->addrlen);

			record_child_data(t, sizeof(child_args->addrlen),
					  child_args->addrlen);
			record_child_data(t, len,
					  child_args->src_addr);
		} else {
			record_noop_data(t);
			record_noop_data(t);
		}

		sys_free((void**)&child_args);
		return;
	}

	/*
	 *  int getsockopt(int sockfd, int level, int optname, const void *optval, socklen_t* optlen);
	 */
	case SYS_GETSOCKOPT: {
		socklen_t** len_ptr = read_child_data(t, sizeof(socklen_t*), (void*)(regs.ecx + 3 * sizeof(int) + sizeof(void*)));
		socklen_t* len = read_child_data(t, sizeof(socklen_t), *len_ptr);
		unsigned long** optval = read_child_data(t, sizeof(void*), (void*)(regs.ecx + 3 * sizeof(int)));
		record_child_data(t, *len, *optval);
		sys_free((void**) &len_ptr);
		sys_free((void**) &len);
		sys_free((void**) &optval);
		return;
	}

	/*
	 *  int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	 *  int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
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
	case SYS_ACCEPT4: {
		long args[4];
		void* addr = pop_arg_ptr(t);
		void* addrlenp = pop_arg_ptr(t);
		void* argsp = pop_arg_ptr(t);
		void* iter;
		void* data = start_restoring_scratch(t, &iter);
		socklen_t len;
		/* Consume the scratch args; nothing there is
		 * interesting to us now. */
		iter += sizeof(args);
		/* addrlen */
		len = *(socklen_t*)iter;
		restore_and_record_arg_buf(t, sizeof(len), addrlenp, &iter);
		/* addr */
		restore_and_record_arg_buf(t, len, addr, &iter);
		/* Restore the pointer to the original args. */
		regs.ecx = (uintptr_t)argsp;
		write_child_registers(tid, &regs);

		finish_restoring_some_scratch(t, iter, &data);
		return;
	}

	/* int socketpair(int domain, int type, int protocol, int sv[2]);
	 *
	 * values returned in sv
	 */
	case SYS_SOCKETPAIR: {
		unsigned long* addr = read_child_data(t, sizeof(int*), (void*)(regs.ecx + (3 * sizeof(int))));
		record_child_data(t, 2 * sizeof(int), (void*)*addr);
		sys_free((void**) &addr);
		return;
	}

	default:
		fatal("Unknown socketcall %d", call);
	}
}

void rec_process_syscall(struct task *t)
{
	/* TODO: extend syscall_defs.h in order to generate code
	 * automatically for the "regular" syscalls.
	 *
	 * Macros to make the recording of syscalls easier. The suffix
	 * denotes the number of buffers that have to be recorded,
	 * which can usually be inferred from the syscall function
	 * signature. */
#define SYS_REC0(syscall) \
	case SYS_##syscall: { \
	break; }


#define SYS_REC1(syscall_,size,addr) \
	case SYS_##syscall_: { \
		record_child_data(t, size, addr); \
	break; }


#define SYS_REC1_STR(syscall_,addr) \
	case SYS_##syscall_: { \
		record_child_str(t, addr); \
	break; }


#define SYS_REC2(syscall_,size1,addr1,size2,addr2) \
	case SYS_##syscall_: { \
		record_child_data(t, size1, addr1);\
		record_child_data(t, size2, addr2); \
	break; }

#define SYS_REC3(syscall_,size1,addr1,size2,addr2,size3,addr3) \
	case SYS_##syscall_: { \
		record_child_data(t, size1, addr1);\
		record_child_data(t, size2, addr2);\
		record_child_data(t, size3, addr3);\
	break; }

#define SYS_REC4(syscall_,size1,addr1,size2,addr2,size3,addr3,size4,addr4) \
	case SYS_##syscall_: { \
		record_child_data(t, size1, addr1);\
		record_child_data(t, size2, addr2);\
		record_child_data(t, size3, addr3);\
		record_child_data(t, size4, addr4);\
		break; }

	pid_t tid = t->tid;
	int syscall = t->ev->syscall.no; /* FIXME: don't shadow syscall() */
	struct user_regs_struct regs;

	read_child_registers(tid, &regs);

	debug("%d: processing syscall: %s(%d) -- time: %u",
	      tid, syscallname(syscall), syscall, get_global_time());

	if (task_desched_rec(t)) {
		const struct syscallbuf_record* rec = task_desched_rec(t);

		assert(t->ev->syscall.tmp_data_ptr != t->scratch_ptr);

		record_parent_data(t,
				   t->ev->syscall.tmp_data_num_bytes,
				   t->ev->syscall.tmp_data_ptr,
				   (void*)rec->extra_data);
		return;
	}

	/* main processing (recording of I/O) */
	switch (syscall) {

	/**
	 * int access(const char *pathname, int mode);
	 *
	 * access()  checks  whether  the calling process can access the file pathname.
	 * If pathname is a symbolic link, it is dereferenced.
	 *
	 */
	SYS_REC0(access)

	/**
	 * unsigned int alarm(unsigned int seconds)
	 *
	 * The alarm() system call schedules an alarm. The process will get a SIGALRM
	 * after the requested amount of seconds.
	 *
	 */
	SYS_REC0(alarm)

	/**
	 * int brk(void *addr)
	 * brk() sets the end of the data segment to the value specified by addr, when that value is
	 * reasonable, the system has enough memory, and the process does not exceed its maximum data size
	 * (see setrlimit(2)).
	 */
	SYS_REC0(brk)

	/** READ NOTE:
	 * int clone(int (*fn)(void *), void *child_stack, int flags, void *arg, (pid_t *ptid, struct user_desc *tls, pid_t *ctid));
	 *
	 * clone()  creates  a new process, in a manner similar to fork(2).  It is actually a library function layered on
	 * top of the underlying clone() system call, hereinafter referred to as sys_clone.  A description  of  sys_clone
	 * is given towards the end of this page.
	 *
	 * NOTE: clone is actually implemented by sys_clone which has the following signature:
	 * long sys_clone(unsigned long clone_flags, unsigned long newsp, void __user *parent_tid, void __user *child_tid, struct pt_regs *regs)
	 *
	 */
	case SYS_clone:
	{
		if (regs.eax < 0)
			break;
		/* record child id here */
		record_child_data_tid(tid, syscall,
				      sizeof(pid_t), (void*)regs.edx);
		record_child_data_tid(tid, syscall,
				      sizeof(pid_t), (void*)regs.esi);
		pid_t new_tid = regs.eax;

		struct user_regs_struct new_regs;
		read_child_registers(new_tid, &new_regs);
		record_child_data_tid(new_tid, syscall,
				      sizeof(struct user_desc),
				      (void*)new_regs.edi);
		record_child_data_tid(new_tid, syscall,
				      sizeof(pid_t), (void*)new_regs.edx);
		record_child_data_tid(new_tid, syscall,
				      sizeof(pid_t), (void*)new_regs.esi);

		break;
	}

	/**
	 *  int creat(const char *pathname, mode_t mode);
	 *
	 * creat() is equivalent to open() with flags equal to
	 * O_CREAT|O_WRONLY|O_TRUNC.
	 */
	SYS_REC0(creat)

	/**
	 * int dup2(int oldfd, int newfd)
	 *
	 * dup2()  makes newfd be the copy of oldfd, closing newfd first if necessary, but note the
	 *  following..
	 */
	SYS_REC0(dup2)

	/**
	 * int close(int fd)
	 *
	 * close()  closes  a file descriptor, so that it no longer refers to any file
	 * and may be reused.  Any record locks (see fcntl(2)) held on the file it was
	 * associated with, and owned by the process,  are removed (regardless of the file
	 *  descriptor that was used to obtain the lock).
	 */
	SYS_REC0(close)

	/**
	 * int chdir(const char *path);
	 *
	 * chdir() changes the current working directory of the calling process to the directory
	 * specified in path.
	 */
	SYS_REC0(chdir)

	/**
	 * int chmod(const char *path, mode_t mode)
	 *
	 * The mode of the file given by path or referenced by fildes is changed
	 */
	SYS_REC0(chmod)

	/**
	 * int clock_getres(clockid_t clk_id, struct timespec *res)
	 *
	 * The  function clock_getres() finds the resolution (precision) of the specified
	 * clock clk_id, and, if res is non-NULL, stores it in the struct timespec pointed
	 * to by res.  The resolution of clocks depends on the implementation and cannot
	 * be configured by a particular process.  If the time value pointed to by  the
	 * argument tp of clock_settime() is not a multiple of res, then it is truncated
	 * to a multiple of res.
	 */
	SYS_REC1(clock_getres, sizeof(struct timespec), (void*)regs.ecx)

	/**
	 * int clock_gettime(clockid_t clk_id, struct timespec *tp);
	 *
	 * The functions clock_gettime() and clock_settime() retrieve and set the time of the
	 * specified clock clk_id.
	 */
	SYS_REC1(clock_gettime, sizeof(struct timespec), (void*)regs.ecx)

	/**
	 * int dup(int oldfd)
	 *
	 * dup() uses the lowest-numbered unused descriptor for the new descriptor.
	 */
	SYS_REC0(dup)

	/**
	 * int epoll_create(int size);
	 *
	 * epoll_create()  creates  an epoll "instance", requesting the kernel to allocate an event backing
	 * store dimensioned for size descriptors.  The size is not the maximum size of the backing store but
	 * just a hint to the kernel about how to dimension internal structures.
	 * When  no  longer  required,  the  file  descriptor returned  by epoll_create() should be closed by using close(2).
	 */
	SYS_REC0(epoll_create)

	/**
	 * int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
	 *
	 * This system call performs control operations on the epoll instance referred to by the file descriptor epfd.
	 * It requests that the operation op be performed for the target file descriptor, fd.
	 *
	 */
	SYS_REC0(epoll_ctl)

	/**
	 * int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
	 *
	 * The  epoll_wait() system call waits for events on the epoll instance referred to by the file descriptor epfd.
	 * The memory area pointed to by events will contain the events that will be available for the caller.  Up
	 * to maxevents are returned by epoll_wait().  The maxevents argument must be greater than zero.
	 */
	case SYS_epoll_wait: {
		void* iter;
		void* data = start_restoring_scratch(t, &iter);
		struct epoll_event* events = pop_arg_ptr(t);
		int maxevents = regs.edx;
		if (events) {
			restore_and_record_arg_buf(t,
						   maxevents * sizeof(*events),
						   events, &iter);
			regs.ecx = (uintptr_t)events;
			write_child_registers(tid, &regs);
		}
		finish_restoring_scratch(t, iter, &data);
		break;
	}

	/**
	 * eventfd()  creates  an  "eventfd  object"  that can be used as an event
	 * wait/notify mechanism by userspace applications, and by the  kernel  to
	 * notify  userspace  applications  of  events.   The  object  contains an
	 * unsigned 64-bit integer (uint64_t) counter that is  maintained  by  the
	 * kernel.   This  counter  is initialized with the value specified in the
	 * argument initval.
	 */
	SYS_REC0(eventfd2)

	/**
	 * int faccessat(int dirfd, const char *pathname, int mode, int flags)
	 *
	 * The  faccessat() system call operates in exactly the same way as access(2), except for the differences
	 * described in this manual page....
	 */
	SYS_REC0(faccessat)

	/**
	 * int posix_fadvise(int fd, off_t offset, off_t len, int advice);
	 *
	 * Programs can use posix_fadvise() to announce an intention to access
	 * file data in a specific pattern in the future, thus allowing the kernel
	 * to perform appropriate optimizations.
	 */
	SYS_REC0(fadvise64)
	SYS_REC0(fadvise64_64)

	/**
	 * int fallocate(int fd, int mode, off_t offset, off_t len);
	 *
	 * fallocate() allows the caller to directly manipulate the allocated disk space
	 * for the file referred to by fd for the byte range starting at offset and
	 * continuing for len bytes
	 */
	SYS_REC0(fallocate)

	/* int fcntl(int fd, int cmd, ... ( arg ));
	 *
	 *
	 * fcntl()  performs  one  of the operations described below on the open file descriptor fd.
	 * The operation is determined by cmd. fcntl() can take an optional third argument.
	 * Whether or not this argument is required is determined by cmd. The required  argument
	 * type is indicated in parentheses after each cmd name (in most cases, the required type is long,
	 * and we identify the argument using the name arg), or void is specified if the argument is not required.
	 */
	case SYS_fcntl64:
	{
		int cmd = regs.ecx;
		switch (cmd) {
		case F_DUPFD:
		case F_GETFD:
		case F_GETFL:
		case F_SETFL:
		case F_SETFD:
		case F_SETOWN:
		case F_SETOWN_EX:
		case F_SETSIG:
			break;

		case F_GETLK64:
		case F_SETLK64:
		case F_SETLKW64:
		case F_GETLK:
		case F_SETLK:
			record_child_data(t, sizeof(struct flock64),
					  (void*)regs.edx);
			break;

		default:
			fatal("Unknown fcntl %d", cmd);
		}
		break;
	}

	/**
	 * int fchdir(int fd);
	 *
	 * fchdir() is identical to chdir(); the only difference is that the directory is given as an open file descriptor.
	 */
	SYS_REC0(fchdir)

	/**
	 * int fchmod(int fd, mode_t mode);
	 *
	 * fchmod() changes the permissions of the file referred to by the open file descriptor fd */
	SYS_REC0(fchmod)

	/**
	 * int fdatasync(int fd)
	 *
	 * fdatasync() is similar to fsync(), but does not flush modified metadata unless that metadata is needed in order
	 * to allow a subsequent data retrieval to be correctly handled.  For example, changes to st_atime or st_mtime (respectively,
	 * time of last access and time of last modification; see stat(2)) do not require flushing because they are not necessary
	 * for a subsequent data read to be handled correctly.  On  the other hand, a change to the file size (st_size, as made by
	 * say ftruncate(2)), would require a metadata flush
	 */
	SYS_REC0(fdatasync)

	/**
	 * void flockfile(FILE * stream)
	 *
	 * The flockfile function acquires the internal locking object associated with the stream stream. This
 	 * ensures that no other thread can explicitly through flockfile/ftrylockfile or implicit through a call of a
 	 * stream function lock the stream. The thread will block until the lock is acquired. An explicit call to
 	 * funlockfile has to be used to release the lock.
 	 *
	 */
	SYS_REC0(flock)

	/**
	 * int fstatfs(int fd, struct statfs *buf)
	 *
	 * The  function  statfs()  returns  information  about  a mounted file system.
	 * path is the pathname of any file within the get_time(GET_TID(thread_id));mounted file system.  buf is a pointer to a
	 * statfs structure defined approximately as follows:
	 *
	 * FIXXME: we use edx here, although according to man pages this system call has only
	 * 2 paramaters. However, strace tells another story...
	 *
	 */
	SYS_REC1(fstatfs, sizeof(struct statfs), (void*)regs.ecx)
	SYS_REC1(fstatfs64, sizeof(struct statfs64), (void*)regs.edx)

	/**
	 * int ftruncate(int fd, off_t length)
	 *
	 * The  truncate() and ftruncate() functions cause the regular file named by path or referenced by fd
	 * to be truncated to a size of precisely length bytes.
	 *
	 */
	SYS_REC0(ftruncate64)
	SYS_REC0(ftruncate)
	SYS_REC0(truncate)

	/**
	 * int fsync(int fd)
	 *
	 * fsync()  transfers ("flushes") all modified in-core data of (i.e., modified buffer cache pages for)
	 * the file referred to by the file descriptor fd to the disk device (or other permanent storage device)
	 * where that file  resides.   The  call  blocks until  the  device  reports that the transfer has
	 * completed.  It also flushes metadata information associated with the file (see stat(2))
	 */
	SYS_REC0(fsync)

	/**
	 * int futex(int *uaddr, int op, int val, const struct timespec *timeout, int *uaddr2, int val3);
	 *
	 * The  futex()  system call provides a method for a program to wait for a
	 * value at a given address to change, and a  method  to  wake  up  anyone
	 * waiting  on a particular address (while the addresses for the same mem‐
	 * ory in separate processes may not be equal, the kernel maps them inter‐
	 * nally  so the same memory mapped in different locations will correspond
	 * for futex() calls).  This system call is typically  used  to  implement
	 * the  contended  case  of  a  lock  in  shared  memory,  as described in
	 * futex(7).
	 *
	 */
	case SYS_futex:
	{
		record_child_data(t, sizeof(int), (void*)regs.ebx);
		int op = regs.ecx & FUTEX_CMD_MASK;

		switch (op) {

		case FUTEX_WAKE:
		case FUTEX_WAIT_BITSET:
		case FUTEX_WAIT:
		case FUTEX_LOCK_PI:
		case FUTEX_UNLOCK_PI:
			break;

		case FUTEX_CMP_REQUEUE:
		case FUTEX_WAKE_OP:
		case FUTEX_CMP_REQUEUE_PI:
		case FUTEX_WAIT_REQUEUE_PI:
			record_child_data(t, sizeof(int), (void*)regs.edi);
			break;

		default:
			log_err("Unknown futex op %d", op);
			sys_exit();
		}

		break;
	}


	/**
	 * char *getcwd(char *buf, size_t size);
	 *
	 * These  functions  return  a  null-terminated  string containing an absolute pathname
	 * that is the current working directory of the calling process.  The pathname is returned as the function result and via the argument buf, if
	 * present.
	 */
	SYS_REC1_STR(getcwd, (void*)regs.ebx)

	/**
	 * int getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
	 *
	 * The system call getdents() reads several linux_dirent structures from the directory referred
	 * to by the open  file  descriptor fd into the buffer pointed to by dirp.  The argument count
	 * specifies the size of that buffer.
	 *
	 */
	SYS_REC1(getdents64, regs.eax, (void*)regs.ecx)
	SYS_REC1(getdents, regs.eax, (void*)regs.ecx)

	/**
	 * gid_t getgid(void);
	 *
	 * getgid() returns the real group ID of the calling process.
	 */
	SYS_REC0(getgid32)

	/**
	 * gid_t getegid(void);
	 *
	 * getegid() returns the effective group ID of the calling process.
	 */
	SYS_REC0(getegid32)

	/**
	 * pid_t getpid(void);
	 *
	 * getpid() returns the process ID of the calling process.
	 * (This is often used by routines that generate unique temporary filenames.)
	 *
	 */
	SYS_REC0(getpid)

	/**
	 * int getgroups(int size, gid_t list[]);
	 *
	 * getgroups()  returns  the  supplementary  group IDs of the calling process in list.
	 * The argument size should be set to the maximum number of items that can be stored in
	 * the buffer pointed to by list. If the calling process is a member of more than size
	 * supplementary groups, then an error results.  It is unspecified whether the effective
	 * group ID of the calling process is included in  the  returned  list. (Thus, an application
	 * should also call getegid(2) and add or remove the resulting value.)

	 *  If size is zero, list is not modified, but the total number of supplementary group IDs for the process
	 *  is returned.  This allows the caller to determine the size of a dynamically allocated list to be  used
	 *  in a further call to getgroups().
	 *
	 * The pointer correction seems to be a bug in ptrace/linux kernel. For some wired reason, the
	 * the value of the ecx register when returning from the systenm call is different from entering
	 * the system call.
	 */
	SYS_REC1(getgroups32, regs.ebx * sizeof(gid_t), (void*)regs.ecx);

	/**
	 * uid_t getuid(void);
	 *
	 *  getuid() returns the real user ID of the calling process
	 */
	SYS_REC0(getuid32)

	/**
	 * uid_t geteuid(void);
	 *
	 * geteuid() returns the effective user ID of the calling process.
	 */
	SYS_REC0(geteuid32)

	/**
	 * pid_t getpgid(pid_t pid);
	 *
	 * getpgid() returns the PGID of the process specified by pid.  If pid is zero,
	 * getpgid() the process ID of the calling process is used.int getrusage(int who, struct rusage *usage);
	 */
	SYS_REC0(getpgid)

	/**
	 * pid_t getppid(void);
	 *
	 * getppid() returns the process ID of the parent of the calling process.
	 */
	SYS_REC0(getppid)

	/**
	 * int getpriority(int which, int who);
	 *
	 * The scheduling priority of the process, process group, or
	 * user, as indicated by which and who is obtained with the
	 * getpriority() call.
	 */
	SYS_REC0(getpriority)

	/**
	 * pid_t gettid(void);
	 *
	 * gettid()  returns  the caller's thread ID (TID).
	 */
	SYS_REC0(gettid)

	/**
	 * int getrusage(int who, struct rusage *usage)
	 *
	 * getrusage() returns resource usage measures for who, which can be one of the following..
	 */
	SYS_REC1(getrusage, sizeof(struct rusage), (void*)regs.ecx)

	/**
	 * int gettimeofday(struct timeval *tv, struct timezone *tz);
	 *
	 * The functions gettimeofday() and settimget_timeofday() can get and set the time as
	 * well as a timezone.  The tv argument is a struct timeval (as specified in <sys/time.h>):
	 *
	 */
	SYS_REC2(gettimeofday,
		 sizeof(struct timeval), (void*)regs.ebx,
		 sizeof(struct timezone), (void*)regs.ecx)

	/**
	 * int inotify_rm_watch(int fd, uint32_t wd)
	 *
	 * inotify_rm_watch()  removes the watch associated with the watch descriptor wd from the
	 * inotify instance associated with the file descriptor fd.
	 */
	SYS_REC0(inotify_rm_watch)

	/**
	 *  int ioctl(int d, int request, ...)
	 *
	 * The ioctl()  function  manipulates the underlying device parameters of
	 * special files.  In particular, many operating characteristics of  char‐
	 * acter  special  files  (e.g., terminals) may be controlled with ioctl()
	 * requests.  The argument d must be an open file descriptor.
	 *
	 * bits    meaning
	 *	31-30	00 - no parameters: uses _IO macro
	 *			10 - read: _IOR
	 *			01 - write: _IOW
	 *			11 - read/write: _IOWR
	 *
	 * 			29-16	size of arguments
	 *
	 * 			15-8	ascii character supposedly
	 *				unique to each driver
	 *
	 * 			7-0	function #
	 * */

	case SYS_ioctl:
	{
		handle_ioctl_request(t, regs.ecx);
		break;
	}

	/**
	 * int ipc(unsigned int call, int first, int second, int third, void *ptr, long fifth);
	 *
	 * ipc()  is  a  common  kernel entry point for the System V IPC calls for
	 * messages, semaphores, and shared memory.   call  determines  which  IPC
	 * function  to  invoke;  the  other  arguments  are passed through to the
	 * appropriate call.
	 *
	 */
	case SYS_ipc:
	{
		int call = regs.ebx;

		switch (call) {

		/* int shmget(key_t key, size_t size, int shmflg); */
		case SHMGET:
		// int semget(key_t key, int nsems, int semflg);
		case SEMGET:
		// int semop(int semid, struct sembuf *sops, unsigned nsops);
		case SEMOP:
		/* int shmdt(const void *shmaddr); */
		case SHMDT:
		{
			break;
		}

		/* void *shmat(int shmid, const void *shmaddr, int shmflg); */
		case SHMAT:
		{
			// the kernel copies the returned address to *third
			record_child_data(t, sizeof(long), (void*)regs.esi);
			break;
		}

		/* int shmctl(int shmid, int cmd, struct shmid_ds *buf); */
		case SHMCTL:
		{
			int cmd = regs.edx;
			(void)cmd;
			assert(cmd != IPC_INFO && cmd != SHM_INFO
			       && cmd != SHM_STAT);
			record_child_data(t, sizeof(struct shmid_ds),
					  (void*)regs.esi);
			break;
		}

		/**
		 *  int semctl(int semid, int semnum, int cmd, union semnum);
		 *
		 *  semnum is optional and determined by cmd

		 * union semun {
               int              val;    // Value for SETVAL
               struct semid_ds *buf;    // Buffer for IPC_STAT, IPC_SET
               unsigned short  *array;  // Array for GETALL, SETALL
               struct seminfo  *__buf;  // Buffer for IPC_INFO (Linux-specific)
           };
		 */
		case SEMCTL:
		{
			int cmd = regs.edx;
			switch (cmd) {
			case IPC_SET:
			case IPC_RMID:
			case GETNCNT:
			case GETPID:
			case GETVAL:
			case GETZCNT:
			case SETALL:
			case SETVAL:
			{
				break;
			}
			case IPC_STAT:
			case SEM_STAT:
			{
				record_child_data(t, sizeof(struct semid_ds),
						  (void*)regs.esi);
				break;
			}

			case IPC_INFO:
			case SEM_INFO:
			{
				record_child_data(t, sizeof(struct seminfo),
						  (void*)regs.esi);
				break;
			}
			case GETALL:
			{
				int semnum = regs.ecx;
				record_child_data(t, semnum * sizeof(unsigned short), (void*)regs.esi);
				break;

			}
			default:
			{
				log_err("Unknown semctl command %d",cmd);
				sys_exit();
				break;
			}
			}
			break;
		}

		/* ssize_t msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg); */
		case MSGRCV:
		{
			record_child_data(t, sizeof(long) + regs.esi,
					  (void*)regs.edx);
			break;
		}

		default:
		log_err("Unknown call in IPC: %d -- bailing out", call);
		sys_exit();
		}

		break;
	}

	/**
	 * int link(const char *oldpath, const char *newpath);
	 *
	 * link() creates a new link (also known as a hard link) to an
	 * existing file.
	 */
	SYS_REC0(link)

	/**
	 * off_t lseek(int fd, off_t offset, int whence)
	 * The  lseek()  function  repositions the offset of the open file associated with the file
	 descriptor fd to the argument offset according to the directive whence as follows:
	 */
	SYS_REC0(lseek)

	/**
	 * int lstat(const char *path, struct stat *buf);
	 *
	 * lstat() is identical to stat(), except that if path is a symbolic link, then
	 * the link itself is stat-ed, not the file that it refers to.
	 */
	SYS_REC1(lstat64, sizeof(struct stat64), (void*)regs.ecx)

	/**
	 * void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
	 *
	 * mmap()  creates  a  new  mapping in the virtual address space of the calling process.
	 * The starting address for the new mapping is specified in addr.  The length argument specifies
	 * the length of the mapping.
	 */
	SYS_REC0(munmap)

	/**
	 * pid_t getpgrp(void)
	 *
	 * The POSIX.1 getpgrp() always returns the PGID of the caller
	 */
	SYS_REC0(getpgrp)

	/**
	 * int inotify_init(void)
	 *
	 * inotify_init()  initializes  a  new inotify instance and returns a file
	 * descriptor associated with a new inotify event queue.
	 */
	SYS_REC0(inotify_init)
	SYS_REC0(inotify_init1)

	/**
	 * int inotify_add_watch(int fd, const char *pathname, uint32_t mask)
	 *
	 * inotify_add_watch()  adds  a  new watch, or modifies an existing watch,
	 * for the file whose location is specified in pathname; the  caller  must
	 * have read permission for this file.  The fd argument is a file descrip
	 * tor referring to the inotify instance whose watch list is to  be  modi‐
	 * fied.   The  events  to  be monitored for pathname are specified in the
	 * mask bit-mask argument.  See inotify(7) for a description of  the  bits
	 * that can be set in mask.
	 */
	SYS_REC0(inotify_add_watch)

	/* int kill(pid_t pid, int sig)
	 *
	 * The kill() system call can be used to send any signal to any process group or process.
	 */
	SYS_REC0(kill)

	/**
	 * long set_robust_list(struct robust_list_head *head, size_t len)
	 *
	 * The robust futex implementation needs to maintain per-thread lists of robust futexes
	 * which are unlocked when the thread exits. These lists are managed in user space, the
	 * kernel is only notified about the location of the head of the list.

	 * set_robust_list sets the head of the list of robust futexes owned by the current thread to head.
	 * len is the size of *head.
	 */
	SYS_REC0(set_robust_list)

	/* int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid);
	 *
	 * getresuid()  returns  the  real  UID,  the effective UID, and the saved set-user-ID of
	 * the calling process, in the arguments ruid, euid, and suid, respectively.  getresgid()
	 * performs the analogous task  for  the  process's  group IDs.
	 * @return:  On success, zero is returned.  On error, -1 is returned, and errno is set appropriately.
	 */
	SYS_REC3(getresgid32,
		 sizeof(uid_t), (void*)regs.ebx,
		 sizeof(uid_t), (void*)regs.ecx,
		 sizeof(uid_t), (void*)regs.edx)

	/**
	 * int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid)
	 *
	 * getresuid() returns the real UID, the effective UID, and the saved set-
	 * user-ID of the calling process, in the arguments ruid, euid, and  suid,
	 * respectively.    getresgid()   performs  the  analogous  task  for  the
	 * process's group IDs.
	 */
	SYS_REC3(getresuid32,
		 sizeof(uid_t), (void*)regs.ebx,
		 sizeof(uid_t), (void*)regs.ecx,
		 sizeof(uid_t), (void*)regs.edx)

	/*
	 * ssize_t lgetxattr(const char *path, const char *name, void *value, size_t size);
	 *
 	 * getxattr() retrieves the value of the extended attribute identified by name
 	 * and associated with the given path in the file system.  The length of the
 	 * attribute value is returned.
 	 *
 	 * lgetxattr() is identical to getxattr(), except in the case of a symbolic link,
 	 * where the link itself is interrogated, not the file that it refers to.
 	 *
 	 * fgetxattr() is identical to getxattr(), only the open file referred to by fd
 	 * (as returned by open(2)) is interrogated in place of path.
 	 *
 	 *
 	 * On success, a positive number is returned indicating the size of the extended
 	 * attribute value.  On failure, -1 is returned and errno is set appropriately.
 	 *
 	 * If the named attribute does not exist, or the process has no access to this
 	 * attribute, errno is set to ENOATTR.
 	 *
 	 * If the size of the value buffer is too small to hold the result, errno is set
 	 * to ERANGE.
 	 *
 	 * If extended attributes are not supported by the file system, or are disabled,
 	 * errno is set to ENOTSUP.
 	 *
	 */
	SYS_REC1(lgetxattr, regs.esi, (void*)regs.edx)


	/*
	 * int _llseek(unsigned int fd, unsigned long offset_high, unsigned long offset_low,
	 * loff_t *result, unsigned int whence);
	 *
	 * The  _llseek()  function  repositions  the offset of the open file associated with the file descriptor fd to (off‐
	 * set_high<<32) | offset_low bytes relative to the beginning of the file, the current position in the file,  or  the
	 * end  of  the  file,  depending on whether whence is SEEK_SET, SEEK_CUR, or SEEK_END, respectively.  It returns the
	 * resulting file position in the argument result.
	 */

	SYS_REC1(_llseek, sizeof(loff_t), (void*)regs.esi)

	/**
	 * int madvise(void *addr, size_t length, int advice);
	 *
	 * The  madvise()  system  call  advises  the  kernel  about how to handle paging input/output
	 * in the address range beginning at address addr and with size length bytes.  It allows an application
	 * to tell the kernel how it expects to use  some  mapped  or shared  memory areas, so that the kernel
	 * can choose appropriate read-ahead and caching techniques.  This call does not influence the semantics
	 * of the application (except in the case of MADV_DONTNEED), but may influence its performance.   The  kernel
	 * is free to ignore the advice.
	 *
	 */
	SYS_REC0(madvise)

	/**
	 * int mkdir(const char *pathname, mode_t mode);
	 *
	 * mkdir() attempts to create a directory named pathname.
	 */
	SYS_REC0(mkdir)

	/**
	 * int mkdirat(int dirfd, const char *pathname, mode_t mode);
	 *
	 * The mkdirat() system call operates in exactly the same way as mkdir(2), except
	 * for the differences described in this manual page....
	 *
	 */
	SYS_REC0(mkdirat)

	/**
	 * int mprotect(const void *addr, size_t len, int prot)
	 *
	 * mprotect()  changes  protection for the calling process's memory page(s) containing any
	 * part of the address range in the interval [addr, addr+len-1].  addr must be aligned to a
	 *  page boundary.

	 * If the calling process tries to access memory in a manner that violates the  protection,  then  the
	 * kernel generates a SIGSEGV signal for the process
	 */
	SYS_REC0(mprotect)

	/**
	 * int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
	 *
	 * select()  and  pselect() allow a program to monitor multiple file descriptors, waiting until one or
	 * more of the file descriptors become "ready" for some class of I/O operation (e.g., input possible).
	 * A file descriptor is considered ready if  it  is possible to perform the corresponding I/O operation
	 * (e.g., read(2)) without blocking.
	 *
	 * We also need to record edi, since the return value of the time struct is not defined
	 */

	SYS_REC4(_newselect,
		 sizeof(fd_set), (void*)regs.ecx,
		 sizeof(fd_set), (void*)regs.edx,
		 sizeof(fd_set), (void*)regs.esi,
		 sizeof(struct timeval), (void*)regs.edi)

	/**
	 * int open(const char *pathname, int flags)
	 * int open(const char *pathname, int flags, mode_t mode)
	 */
	case SYS_open:
	{
		char *pathname = read_child_str(tid, (void*)regs.ebx);
		if (is_blacklisted_filename(pathname)) {
			/* NB: the file will still be open in the
			 * process's file table, but let's hope this
			 * gross hack dies before we have to worry
			 * about that. */
			log_warn("Cowardly refusing to open %s", pathname);
			regs.eax = -ENOENT;
			write_child_registers(tid, &regs);
		}
		sys_free((void**)&pathname);
		break;
	}

	/**
	 * int openat(int dirfd, const char *pathname, int flags);
	 * int openat(int dirfd, const char *pathname, int flags, mode_t mode);
	 *
	 * The  openat() system call operates in exactly the same way as open(2), except for the
	 * differences described in this manual page.
	 */
	SYS_REC0(openat)

	/**
	 *  int perf_event_open(struct perf_event_attr *attr,
	 *                      pid_t pid, int cpu, int group_fd,
         *                      unsigned long flags);
	 *
	 * Given a list of parameters, perf_event_open() returns a
	 * file descriptor, for use in subsequent system calls
	 * (read(2), mmap(2), prctl(2), fcntl(2), etc.).
	 */
	SYS_REC0(perf_event_open)

	/**
	 *  int pipe(int pipefd[2]);
	 *
	 * pipe()  creates  a  pipe, a unidirectional data channel that can be used for
	 * interprocess communiinotify_init1cation.  The array pipefd is used  to  return  two  file
	 * descriptors referring to the ends of the pipe.  pipefd[0] refers to the read
	 * end of the pipe.  pipefd[1] refers to the write end of the pipe.  Data writ‐
	 * ten  to the write end of the pipe is buffered by the kernel until it is read
	 * from the read end of the pipe.  For further details, see pipe(7).
	 */
	SYS_REC2(pipe,
		 sizeof(int), (void*)regs.ebx,
		 sizeof(int), (void*)(regs.ebx+sizeof(int*)))

	/**
	 * int pipe2(int pipefd[2], int flags)
	 *
	 * If flags is 0, then pipe2() is the same as pipe().  The following values can be bitwise
	 * ORed in flags to obtain different behavior...
	 */
	SYS_REC2(pipe2,
		 sizeof(int), (void*)regs.ebx,
		 sizeof(int), (void*)(regs.ebx+sizeof(int*)))

	/**
	 * int poll(struct pollfd *fds, nfds_t nfds, int timeout)
	 * int ppoll(struct pollfd *fds, nfds_t nfds,
	 *           const struct timespec *timeout_ts,
	 *           const sigset_t *sigmask);
	 *
	 * poll() performs a similar task to select(2): it waits for
	 * one of a set of file descriptors to become ready to perform
	 * I/O.
	 *
	 * The relationship between poll() and ppoll() is analogous to
	 * the relationship between select(2) and pselect(2): like
	 * pselect(2), ppoll() allows an application to safely wait
	 * until either a file descriptor becomes ready or until a
	 * signal is caught.
	 */
	case SYS_poll:
	case SYS_ppoll: {
		void* iter;
		void* data = start_restoring_scratch(t, &iter);
		struct pollfd* fds = pop_arg_ptr(t);
		size_t nfds = regs.ecx;

		restore_and_record_arg_buf(t, nfds * sizeof(*fds), fds,
					   &iter);
		regs.ebx = (uintptr_t)fds;
		write_child_registers(tid, &regs);
		finish_restoring_scratch(t, iter, &data);
		break;
	}

	/**
	 * int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
	 *
	 *  prctl() is called with a first argument describing what to do (with values defined in <linux/prctl.h>), and
	 *  further arguments with a significance depending on the first one.
	 *
	 */
	case SYS_prctl:	{
		int size;
		switch (regs.ebx) {
			/* See rec_prepare_syscall() for how these
			 * sizes are determined. */
			case PR_GET_ENDIAN:
			case PR_GET_FPEMU:
			case PR_GET_FPEXC:
			case PR_GET_PDEATHSIG:
			case PR_GET_TSC:
			case PR_GET_UNALIGN:
				size = sizeof(int);
				break;
			case PR_GET_NAME:
				size = 16;
				break;
			default:
				size = 0;
				break;
		}
		if (size > 0) {
			void* iter;
			void* data = start_restoring_scratch(t, &iter);
			void* arg = pop_arg_ptr(t);

			restore_and_record_arg_buf(t, size, arg, &iter);
			regs.ecx = (uintptr_t)arg;
			write_child_registers(tid, &regs);

			finish_restoring_scratch(t, iter, &data);
		} else {
			record_noop_data(t);
		}
		break;
	}
	
	/**
	 * ssize_t pread(int fd, void *buf, size_t count, off_t offset);
	 *
	 * pread, pwrite - read from or write to a file descriptor at a given off‐
	 * set
	 */
	SYS_REC1(pread64, regs.eax, (void*)regs.ecx)
	SYS_REC0(pwrite64)

	/**
	 *  int prlimit(pid_t pid, int resource, const struct rlimit *new_limit, struct rlimit *old_limit);
	 *
	 * The Linux-specific prlimit() system call combines and extends the
	 * functionality of setrlimit() and getrlimit().  It can be used to both set and
	 * get the resource limits of an arbitrary process.
	 *
	 * The resource argument has the same meaning as for setrlimit() and getrlimit().
	 *
	 * If the new_limit argument is a not NULL, then the rlimit structure to which it
	 * points is used to set new values for the soft and hard limits for resource.
	 * If the old_limit argument is a not NULL, then a successful call to prlimit()
	 * places the previous soft and hard limits for resource in the rlimit structure
	 * pointed to by old_limit.
	 */
	SYS_REC1(prlimit64, sizeof(struct rlimit64), (void*)regs.esi)

	/**
	 * int quotactl(int cmd, const char *special, int id, caddr_t addr);
	 *
	 * The  quotactl()  call  manipulates disk quotas.  The cmd argument indi‐
	 * cates a command to be applied to the user or group ID specified in  id.
	 * To  initialize the cmd argument, use the QCMD(subcmd, type) macro.  The
	 * type value is either USRQUOTA, for user quotas, or GRPQUOTA, for  group
	 * quotas.  The subcmd value is described below.
	 */
	case SYS_quotactl:
	 {
		 int cmd = regs.ebx;
		 void* addr = (void*)regs.esi;
		 switch (cmd & SUBCMDMASK) {
		 case Q_GETQUOTA:
		 // Get disk quota limits and current usage for user or group id. The addr argument is a pointer to a dqblk structure 
		 	 record_child_data(t, sizeof(struct dqblk), addr);
		 	 break;
		 case Q_GETINFO:
		 // Get information (like grace times) about quotafile. The addr argument should be a pointer to a dqinfo structure 
		 	 record_child_data(t, sizeof(struct dqinfo), addr);
		 	 break;
		 case Q_GETFMT:
		 // Get quota format used on the specified file system. The addr argument should be a pointer to a 4-byte buffer 
		 	 record_child_data(t, 4, addr);
		 	 break;

		 /**
		  * case Q_GETSTATS:
		  * This operation is obsolete and not supported by recent kernels.
		  * Get statistics and other generic information about the quota subsystem. The addr argument should be a pointer to a dqstats structure
		  */

		 case Q_SETQUOTA:
		 	 assert(0 && "Warning: trying to set disk quota usage, this may interfere with rr recording");
		 	 break;

		 /**
		  * XFS file systems
		  *
		  * case Q_XGETQUOTA:
		  * case Q_XGETQSTAT:
		  */

		 default:
		 	 break;
		 }

		 break;
	 }

	/**
	 * ssize_t readahead(int fd, off64_t offset, size_t count);
	 *
	 * readahead()  populates the page cache with data from a file so that subsequent reads from that file will not block
	 * on disk I/O.  The fd argument is a file descriptor identifying the file which is to be read.  The offset argu-
	 * ment specifies the starting point from which data is to be read and count specifies the number of bytes to be read.
	 * I/O is performed in whole pages, so that offset is effectively rounded down to a page boundary and bytes are
	 * read  up  to  the  next page boundary greater than or equal to (offset+count).  readahead() does not read
	 * beyond the end of the file.  readahead() blocks until the specified data has been read.  The current file offset of the
	 * open file referred to by fd is left unchanged.
	 */
	SYS_REC0(readahead)

	/**
	 * ssize_t readlink(const char *path, char *buf, size_t bufsiz);
	 *
	 * readlink() places the contents of the symbolic link path in the buffer
	 * buf, which has size bufsiz. readlink() does not append a null byte to buf.
	 * It will truncate the contents (to a length of bufsiz characters), in case
	 * the buffer is too small to hold all of the contents.
	 */
	SYS_REC1(readlink, regs.edx, (void*)regs.ecx)

	/**
	 * int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
	 *
	 * The sigaction() system call is used to change the action taken by a process on receipt of a
	 * specific signal.  (See signal(7) for an overview of signals.)
	 *
	 * signum specifies the signal and can be any valid signal except SIGKILL and SIGSTOP.
	 *
	 * If act is non-NULL, the new action for signal signum is installed from act.  If oldact is non-NULL, the  previous  action  is
	 * saved in oldact.
	 *
	 */
	case SYS_rt_sigaction: {
		int sig = regs.ebx;
		void* new_sigaction = (void*)regs.ecx;
		void* old_sigaction = (void*)regs.edx;

		record_child_data(t, sizeof(struct sigaction), old_sigaction);
		if (0 == regs.eax && new_sigaction) {
			/* A new sighandler was installed.  Update t's
			 * sighandler table. */
			struct sigaction* sa = read_child_data(t, sizeof(*sa),
							       new_sigaction);
			sig_handler_t sh = (sa->sa_flags & SA_SIGINFO) ?
					   (void*)sa->sa_sigaction :
					   sa->sa_handler;
			int resethand = (sa->sa_flags & SA_RESETHAND);

			sighandlers_set_disposition(t->sighandlers, sig,
						    sh, resethand);

			sys_free((void**)&sa);
		}
		break;
	 }
	 /* TODO: SYS_signal, SYS_sigaction */

	/**
	 *  int sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
	 *
	 *  sigprocmask() is used to fetch and/or change the signal mask of the calling
	 *  thread.  The signal mask is the set of signals whose delivery is currently
	 *   blocked for the caller (see also signal(7) for more details).
	 */
	SYS_REC1(sigprocmask, sizeof(sigset_t), (void*)regs.edx)
	SYS_REC1(rt_sigprocmask, sizeof(sigset_t), (void*)regs.edx)

	/**
	 * int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask);
	 *
	 * sched_getaffinity()  writes  the affinity mask of the process whose ID is pid into the cpu_set_t structure
	 * pointed to by mask.  The cpusetsize argument specifies the
	 *  size (in bytes) of mask.  If pid is zero, then the mask of the calling process is returned.
	 */
	SYS_REC1(sched_getaffinity, sizeof(cpu_set_t), (void*)regs.edx)

	/**
	 * int sched_getparam(pid_t pid, struct sched_param *param)
	 *
	 * sched_getparam()  retrieves  the  scheduling  parameters  for  the  process  i
	 * dentified  by  pid.  If pid is zero, then the parameters of the calling process
	 * are retrieved.
	 */
	SYS_REC1(sched_getparam, sizeof(struct sched_param), (void*)regs.ecx)

	/**
	 *  int sched_get_priority_max(int policy)
	 *
	 * sched_get_priority_max() returns the maximum priority value that can be
	 * used    with   the   scheduling   algorithm   identified   by   policy.
	 */
	SYS_REC0(sched_get_priority_max)

	/**
	 * int sched_get_priority_min(int policy)
	 *
	 * sched_get_priority_min() returns the minimint fdatasync(int fd);um priority value that can be used
	 * with the scheduling algorithm identified by  policy.
	 */
	SYS_REC0(sched_get_priority_min)

	/**
	 * int sched_getscheduler(pid_t pid);
	 *
	 * sched_getscheduler() queries the scheduling policy currently applied to the
	 * process identified by pid.  If pid equals zero, the policy  of  the  calling
	 * process will be retrieved.
	 */
	SYS_REC0(sched_getscheduler)

	/**
	 * int sched_setscheduler(pid_t pid, int policy, const struct sched_param *param);
	 *
	 * sched_setscheduler()  sets  both the scheduling policy and the associated parameters
	 * for the process whose ID is specified in pid.  If pid equals zero, the scheduling policy
	 * and parameters of the calling process will be set.  The interpretation of the argument
	 * param depends on the selected policy.
	 */
	SYS_REC0(sched_setscheduler)

	/**
	 * int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask);
	 *
	 * sched_setaffinity()  sets the CPU affinity mask of the process whose ID
	 * is pid to the value specified by mask.  If pid is zero, then the  call‐
	 * ing  process is used.  The argument cpusetsize is the length (in bytes)
	 * of the data pointed to by mask.  Normally this argument would be speci‐
	 * fied as sizeof(cpu_set_t).
	 */
	SYS_REC0(sched_setaffinity)

	/**
	 * int sched_yield(void)
	 *
	 * sched_yield() causes the calling thread to relinquish the CPU.  The thread is moved to the end of
	 * the queue for its static priority and a new thread gets to run.
	 */
	SYS_REC0(sched_yield)

	/**
	 * int setitimer(int which, const struct itimerval *new_value, struct itimerval *old_value);
	 *
	 */
	SYS_REC1(setitimer, sizeof(struct itimerval), (void*)regs.edx);

	/**
	 * int setpriority(int which, int who, int prio);
	 *
	 * The scheduling priority of the process, process group, or
	 * user, as indicated by which and who is set with the
	 * setpriority() call.
	 */
	SYS_REC0(setpriority)

	/**
	 * int setregid(gid_t rgid, gid_t egid)
	 *
	 * setreuid() sets real and effective user IDs of the calling process
	 */
	SYS_REC0(setregid32)

	/**
	 * int setresgid(gid_t rgid, gid_t egid, gid_t sgid);
	 *
	 * setresgid() sets the real GID, effective GID, and saved set-group-ID of the calling process.
	 *
	 */
	SYS_REC0(setresgid32)

	/**
	 * int setresuid(uid_t ruid, uid_t euid, uid_t suid);
	 *
	 * setresuid() sets the real user ID, the effective user ID, and the saved set-user-ID of the calling process.
	 *
	 */
	SYS_REC0(setresuid32)

	/**
	 * pid_t setsid(void);
	 *
	 * setsid() creates a new session if the calling process is not a process group leader.
	 */
	SYS_REC0(setsid)

	/**
	 * int set_thread_area(struct user_desc *u_info)
	 *
	 * set_thread_area()  sets  an  entry in the current thread's Thread Local
	 * Storage (TLS) array.  The TLS array entry set by set_thread_area() cor‐
	 * responds  to  the  value of u_info->entry_number passed in by the user.
	 * If this value is in bounds, set_thread_area() copies the TLS descriptor
	 * pointed to by u_info into the thread's TLS array.
	 *
	 * When  set_thread_area() is passed an entry_number of -1, it uses a free
	 * TLS entry.  If set_thread_area() finds a free TLS entry, the  value  of
	 * u_info->entry_number  is  set  upon  return  to  show  which  entry was
	 * changed.
	 *
	 */
	SYS_REC1(set_thread_area, sizeof(struct user_desc), (void*)regs.ebx);

	/**
	 * long set_tid_address(int *tidptr);
	 *
	 * The kernel keeps for each process two values called set_child_tid and clear_child_tid
	 * that are NULL by default.
	 *
	 * If  a  process  is  started  using  clone(2)  with   the   CLONE_CHILD_SETTID   flag,
	 * set_child_tid is set to child_tidptr, the fifth argument of that system call.
	 *
	 * When  set_child_tid  is set, the very first thing the new process does is writing its
	 * PID at this address.
	 *
	 */
	SYS_REC1(set_tid_address, sizeof(int), (void*)regs.ebx)

	/**
	 * int sigaltstack(const stack_t *ss, stack_t *oss)
	 *
	 * sigaltstack()  allows a process to define a new alternate signal stack and/or retrieve the state of
	 * an existing alternate signal stack.  An alternate signal stack is used during the execution of a signal
	 * handler if the establishment of that handler (see sigaction(2)) requested it.
	 */
	SYS_REC1(sigaltstack, regs.ecx ? sizeof(stack_t) : 0, (void*)regs.ecx)

	/**
	 * int sigreturn(unsigned long __unused)
	 *
	 * When  the Linux kernel creates the stack frame for a signal handler, a call to sigreturn()
	 * is inserted into the stack frame so that upon return from the signal handler, sigreturn() will
	 * be called.
	 */
	SYS_REC0(sigreturn)

	/**
	 * int socketcall(int call, unsigned long *args)
	 *
	 * socketcall()  is  a common kernel entry point for the socket system calls.  call determines
	 * which socket function to invoke.  args points to a block containing the actual arguments,
	 * which  are  passed  through  to  the appropriate call.
	 *
	 */
	case SYS_socketcall:
		return process_socketcall(t, &regs,
					  regs.ebx, (void*)regs.ecx);

	/**
	 *  int stat(const char *path, struct stat *buf);
	 *
	 *  stat() stats the file pointed to by path and fills in buf.
	 */
	SYS_REC1(stat64, sizeof(struct stat64), (void*)regs.ecx)

	/**
	 * int statfs(const char *path, struct statfs *buf)
	 *
	 * The function statfs() returns information about a mounted file system.  path is the pathname of any file within the mounted
	 * file system.  buf is a pointer to a statfs structure defined approximately as follows:
	 */
	SYS_REC1(statfs, sizeof(struct statfs), (void*)regs.ecx)

	/**
	 * int statfs(const char *path, struct statfs *buf)
	 *
	 * The  function  statfs() returns information about a mounted file system.
	 * path is the pathname of any file within the mounted file system.  buf is a
	 * pointer to a statfs structure defined approximately as follows:
	 *
	 * FIXXME: we use edx here, although according to man pages this system call has only
	 * 2 paramaters. However, strace tells another story...
	 */
	SYS_REC1(statfs64, sizeof(struct statfs64), (void*)regs.edx)

	/**
	 * int symlink(const char *oldpath, const char *newpath)
	 *
	 * symlink() creates a symbolic link named newpath which contains the string oldpath.
	 */
	SYS_REC0(symlink)

	/**
	 * int sysinfo(struct sysinfo *info)
	 *
	 * sysinfo() provides a simple way of getting overall system statistics.
	 */
	SYS_REC1(sysinfo, sizeof(struct sysinfo), (void*)regs.ebx)

	/**
	 * int tgkill(int tgid, int tid, int sig)
	 * tgkill()  sends  the  signal sig to the thread with the thread ID tid in the thread group tgid.  (By contrast, kill(2) can only be used to send a
	 * signal to a process (i.e., thread group) as a whole, and the signal will be delivered to an arbitrary thread within that process.)
	 */
	case SYS_tgkill:
	{
		break;
	}

	/**
	 * time_t time(time_t *t);
	 *
	 * time() returns the time since the Epoch (00:00:00 UTC, January 1, 1970), measured
	 *  in seconds. If t is non-NULL, the return value is also stored in the memory pointed
	 *  to by t.
	 */
	SYS_REC1(time, sizeof(time_t), (void*)regs.ebx)

	/**
	 * clock_t times(struct tms *buf)
	 *
	 * times()  stores  the  current  process  times in the struct tms that buf points to.  The
	 *  struct tms is as defined in <sys/times.h>:
	 */
	SYS_REC1(times, sizeof(struct tms), (void*)regs.ebx)

	/**
	 * int getrlimit(int resource, struct rlimit *rlim)
	 *
	 * getrlimit()  and  setrlimit()  get and set resource limits respectively.
	 * Each resource has an associated soft and hard limit, as defined by the rlimit structure
	 * (the rlim argument to both getrlimit() and setrlimit()):
	 */
	SYS_REC1(ugetrlimit, sizeof(struct rlimit), (void*)regs.ecx)

	/**
	 * int uname(struct utsname *buf)
	 *
	 * uname() returns system information in the structure pointed to by buf. The utsname
	 * struct is defined in <sys/utsname.h>:
	 */
	SYS_REC1(uname, sizeof(struct utsname), (void*)regs.ebx)

	/**
	 * int utime(const char *filename, const struct utimbuf *times)
	 *
	 * The  utime()  system call changes the access and modification times of the inode specified by
	 * filename to the actime and modtime fields of times respectively.
	 *
	 * If times is NULL, then the access and modification times of the file are set to the current time.
	 *
	 * Changing timestamps is permitted when: either the process has appropriate privileges, or the effective  user  ID  equals  the
	 * user ID of the file, or times is NULL and the process has write permission for the file.
	 */
	SYS_REC0(utime)

	/**
	 * int utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags);
	 *
	 * utimensat() and futimens() update the timestamps of a file with nanosecond precision.  This
	 * contrasts with the historical utime(2) and utimes(2), which permit only second and microsecond precision,
	 * respectively, when setting file timestamps.
	 */
	SYS_REC0(utimensat)

	/* signature:
	 * int execve(const char *filename, char *const argv[], char *const envp[]);
	 *
	 */
	case SYS_execve:
	{

		if (regs.ebx != 0) {
			break;
		}

		unsigned int* stack_ptr = (unsigned int*) read_child_esp(tid);
		/* start_stack points to argc - iterate over argv pointers */

		/* FIXME: there are special cases, like when recording gcc, where the esp does not
		 *        point to argc. For example, it may point to &argc.
		 */
		int* argc = read_child_data(t, sizeof(unsigned long), stack_ptr);
		stack_ptr += *argc + 1;
		sys_free((void**) &argc);

		unsigned long* null_ptr = read_child_data(t, sizeof(void*), stack_ptr);
		assert(*null_ptr == 0);

		sys_free((void**) &null_ptr);

		stack_ptr++;

		/* should now point to envp (pointer to environment strings) */
		unsigned long* tmp = read_child_data(t, sizeof(unsigned long*), stack_ptr);

		while (*tmp != 0) {
			sys_free((void**) &tmp);
			stack_ptr++;
			tmp = read_child_data(t, sizeof(unsigned long*), stack_ptr);
		}
		sys_free((void**) &tmp);
		stack_ptr++;

		/* should now point to ELF Auxiliary Table */

		tmp = read_child_data(t, sizeof(unsigned long*), stack_ptr);
		assert(*tmp == 0x20);
		/* AT_SYSINFO */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(t, sizeof(unsigned long*), stack_ptr);
		assert(*tmp == 0x21);
		/* AT_SYSINFO_EHDR */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(t, sizeof(unsigned long*), stack_ptr);
		assert(*tmp == 0x10);
		/* AT_HWCAP */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(t, sizeof(unsigned long*), stack_ptr);
		assert(*tmp == 0x6);
		/* AT_PAGESZ */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(t, sizeof(unsigned long*), stack_ptr);
		assert(*tmp == 0x11);
		/* AT_CLKTCK */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(t, sizeof(unsigned long*), stack_ptr);
		assert(*tmp == 0x3);
		/* AT_PHDR */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(t, sizeof(unsigned long*), stack_ptr);
		assert(*tmp == 0x4);
		/* AT_PHENT */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(t, sizeof(unsigned long*), stack_ptr);
		assert(*tmp == 0x5);
		/* AT_PHNUM */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(t, sizeof(unsigned long*), stack_ptr);
		assert(*tmp == 0x7);
		/* AT_BASE */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(t, sizeof(unsigned long*), stack_ptr);
		assert(*tmp == 0x8);
		/* AT_FLAGS */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(t, sizeof(unsigned long*), stack_ptr);
		assert(*tmp == 0x9);
		/* AT_ENTRY */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(t, sizeof(unsigned long*), stack_ptr);
		assert(*tmp == 0xb);
		/* AT_UID */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(t, sizeof(unsigned long*), stack_ptr);
		assert(*tmp == 0xc);
		/* AT_EUID */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(t, sizeof(unsigned long*), stack_ptr);
		assert(*tmp == 0xd);
		/* AT_GID */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(t, sizeof(unsigned long*), stack_ptr);
		assert(*tmp == 0xe);
		/* AT_EGID */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(t, sizeof(unsigned long*), stack_ptr);
		assert(*tmp == 0x17);
		/* AT_SECURE */
		sys_free((void**) &tmp);
		stack_ptr += 2;

		tmp = read_child_data(t, sizeof(unsigned long*), stack_ptr);
		assert(*tmp == 0x19);
		/* AT_RANDOM */
		unsigned long* rand_addr = read_child_data(t, sizeof(unsigned long*), (stack_ptr + 1));
		record_child_data(t, 16, (void*)*rand_addr);

		sys_free((void**) &rand_addr);
		sys_free((void**) &tmp);
		break;
	}

	/**
	 * int fstat(int fd, struct stat *buf)
	 *
	 * fstat()  is  identical  to  stat(),  except  that  the  file to be stat-ed is specified
	 * by the file descriptor fd.
	 *
	 */

	SYS_REC1(fstat64, sizeof(struct stat64), (void*)regs.ecx)

	/**
	 * int fstatat(int dirfd, const char *pathname, struct stat *buf, int flags);
	 *
	 * The  fstatat()  system  call operates in exactly the same way as stat(2), except for the
	 * differences described in this manual page....
	 */
	SYS_REC1(fstatat64, sizeof(struct stat64), (void*)regs.edx)

	/**
	 * pid_t fork(void)
	 *
	 * fork()  creates  a new process by duplicating the calling process.  The new process, referred to as
	 * the child, is an exact duplicate of the calling process, referred to as the parent, except for the
	 * following points...
	 *
	 */
	SYS_REC0(fork)

	/**
	 *  void *mmap2(void *addr, size_t length, int prot,int flags, int fd, off_t pgoffset);
	 *
	 * The mmap2() system call operates in exactly the same way as
	 * mmap(2), except that the final argument specifies the
	 * offset into the file in 4096-byte units (instead of bytes,
	 * as is done by mmap(2)).  This enables applications that use
	 * a 32-bit off_t to map large files (up to 2^44 bytes).
	 */
	case SYS_mmap2:
	{
		void* addr = (void*)regs.eax;
		size_t size = PAGE_ALIGN(regs.ecx);
		int prot = regs.edx, flags = regs.esi;
		struct mmapped_file file;
		char* filename;

		if (SYSCALL_FAILED(regs.eax)) {
			/* We purely emulate failed mmaps. */
			break;
		}
		if (flags & MAP_ANONYMOUS) {
			/* Anonymous mappings are by definition not
			 * backed by any file-like object, and are
			 * initialized to zero, so there's no
			 * nondeterminism to record. */
			/*assert(!(flags & MAP_UNINITIALIZED));*/
			break;
		}

		assert(!(flags & MAP_GROWSDOWN));
		
		file.time = get_global_time();
		file.tid = tid;

		filename = get_mmaped_region_filename(t, addr);
		strcpy(file.filename, filename);
		sys_free((void**)&filename);

		if (stat(file.filename, &file.stat)) {
			fatal("Sorry, mmap()'ing anonymous shmem regions is NYI.");
		}
		file.start = addr;
		file.end = get_mmaped_region_end(t, addr);

		if (strstr(file.filename, SYSCALLBUF_LIB_FILENAME)
		    && (prot & PROT_EXEC) ) {
			t->syscallbuf_lib_start = file.start;
			t->syscallbuf_lib_end = file.end;
		}

		file.copied = should_copy_mmap_region(file.filename,
						      &file.stat,
						      prot, flags);
		if (file.copied) {
			record_child_data(t, size, addr);
		}
		/* TODO: fault on accesses to SHARED mappings we think
		 * might actually be written */

		record_mmapped_file_stats(&file);
		break;
	}

	/*
	 * void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, ... ( void *new_address ));
	 *
	 *  mremap()  expands  (or  shrinks) an existing memory mapping, potentially moving it at the same time
	 *  (controlled by the flags argument and the available virtual address space).
	 */
	SYS_REC0(mremap)

	/**
	 * int nanosleep(const struct timespec *req, struct timespec *rem)
	 *
	 * nanosleep()  suspends  the  execution  of the calling thread until either at least the time specified in *req has
	 * elapsed, or the delivery of a signal that triggers the invocation of a handler in the calling thread or that ter-
	 * minates the process.
	 */
	case SYS_nanosleep:
	{
		struct timespec* rem = pop_arg_ptr(t);
		void* iter;
		void* data = start_restoring_scratch(t, &iter);

		if (rem) {
			/* If the sleep completes, the kernel doesn't
			 * write back to the remaining-time
			 * argument. */
			if (0 == regs.eax) {
				record_noop_data(t);
			} else {
				/* TODO: where are we supposed to
				 * write back these args?  We don't
				 * see an EINTR return from
				 * nanosleep() when it's interrupted
				 * by a user-handled signal. */
				restore_and_record_arg_buf(t, sizeof(*rem),
							   rem,
							   &iter);
			}
			regs.ecx = (uintptr_t)rem;
			write_child_registers(tid, &regs);
		}

		finish_restoring_some_scratch(t, iter, &data);
		break;
	}

	/**
	 * int rmdir(const char *pathname)
	 *
	 * rmdir() deletes a directory, which must be empty.
	 */
	SYS_REC0(rmdir)

	/**
	 * ssize_t write(int fd, const void *buf, size_t count)
	 *
	 * write() writes up to count bytes to the file referenced by the file descriptor fd
	 * write()  from the buffer starting at buf. POSIX requires that a read() which can be
	 * proved to occur after a write() has returned returns the new data. Note that not all file
	 *  systems are POSIX conforming.
	 */
	SYS_REC0(write)

	/*
	 * ssize_t read(int fd, void *buf, size_t count);
	 *
	 * read() attempts to read up to count bytes from file descriptor fd into the buffer starting at buf.
	 * On success, the number of bytes read is returned (zero indicates end of file), and the file position
	 * is advanced by this number. It is not an error if this number is smaller than the number of bytes
	 * requested; this may happen for example because fewer bytes are actually available right now (maybe
	 * because we were close to end-of-file, or because we are reading from a pipe, or from a terminal),
	 * or because read() was interrupted by a signal. On error, -1 is returned, and errno is set appropriately.
	 * In this case it is left unspecified whether the file position (if any) changes.
	 */
	case SYS_read: {
		void* buf;
		ssize_t nread;
		void* iter;
		void* data = NULL;

		nread = regs.eax;
		if (has_saved_arg_ptrs(t)) {
			buf = pop_arg_ptr(t);
			data = start_restoring_scratch(t, &iter);
		} else {
			buf = (void*)regs.ecx;
		}

		if (nread > 0) {
			if (data) {
				restore_and_record_arg_buf(t, nread, buf,
							   &iter);
			} else {
				record_child_data(t, nread, buf);
			}
		} else {
			record_noop_data(t);
		}

		if (data) {
			regs.ecx = (uintptr_t)buf;
			write_child_registers(tid, &regs);
			finish_restoring_some_scratch(t, iter, &data);
		}
		break;
	}

	/**
	 *  int recvmmsg(int sockfd, struct mmsghdr *msgvec,
	 *               unsigned int vlen, unsigned int flags,
	 *               struct timespec *timeout);
	 *
	 * The recvmmsg() system call is an extension of recvmsg(2)
	 * that allows the caller to receive multiple messages from a
	 * socket using a single system call.  (This has performance
	 * benefits for some applications.)  A further extension over
	 * recvmsg(2) is support for a timeout on the receive
	 * operation.
	 */
	case SYS_recvmmsg: {
		struct mmsghdr* msg = (void*)regs.ecx;
		ssize_t nmmsgs = regs.eax;
		int i;

		for (i = 0; i < nmmsgs; ++i, ++msg) {
			record_struct_mmsghdr(t, msg);
		}
		break;
	}

	/**
	 * int rename(const char *oldpath, const char *newpath)
	 *
	 * rename() renames a file, moving it between directories if required.
	 */
	SYS_REC0(rename)

	/**
	 *  int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
	 *               unsigned int flags);
	 *
	 * The sendmmsg() system call is an extension of sendmsg(2)
	 * that allows the caller to transmit multiple messages on a
	 * socket using a single system call.  (This has performance
	 * benefits for some applications.)
	 */
	case SYS_sendmmsg: {
		struct mmsghdr* msg = (void*)regs.ecx;
		ssize_t nmmsgs = regs.eax;
		int i;

		/* Record the outparam msg_len fields. */
		for (i = 0; i < nmmsgs; ++i, ++msg) {
			record_child_data(t, sizeof(msg->msg_len),
					  &msg->msg_len);
		}
		break;
	}

	/**
	 * int setpgid(pid_t pid, pid_t pgid);
	 *
	 * setpgid()  sets the PGID of the process specified by pid to pgid.  If pid is zero, then
	 * the process ID of the calling process is used.  If pgid is zero, then the PGID of the
	 * process specified by pid is made the same as its process ID.  If setpgid() is used  to
	 * move  a process from one process group to another (as is done by some shells when creating
	 * pipelines), both process groups must be part of the same session (see setsid(2) and
	 * credentials(7)).  In this case, the  pgid  specifies  an  existing process group to be
	 * joined and the session ID of that group must match the session ID of the joining process.
	 */
	SYS_REC0(setpgid)

	/**
	 * int setrlimit(int resource, const struct rlimit *rlim)
	 *
	 *  getrlimit() and setrlimit() get and set resource limits respectively.  Each resource has an associated soft and hard limit, as
	 defined by the rlimit structure (the rlim argument to both getrlimit() and setrlimit()):

	 struct rlimit {
	 rlim_t rlim_cur;  // Soft limit
	 rlim_t rlim_max;  // Hard limit (ceiling for rlim_cur)
	 };

	 The soft limit is the value that the kernel enforces for the corresponding resource.  The hard limit acts as a ceiling for the
	 soft  limit:  an  unprivileged  process  may  only set its soft limit to a value in the range from 0 up to the hard limit, and
	 (irreversibly) lower its hard limit.  A privileged process (under Linux: one with the CAP_SYS_RESOURCE  capability)  may  make
	 arbitrary changes to either limit value.
	 */
	SYS_REC1(setrlimit, sizeof(struct rlimit), (void*)regs.ecx)

	/**
	 * ssize_t splice(int fd_in, loff_t *off_in, int fd_out,
	 *                loff_t *off_out, size_t len, unsigned int flags);
	 *
	 * splice() moves data between two file descriptors without
	 * copying between kernel address space and user address
	 * space.  It transfers up to len bytes of data from the file
	 * descriptor fd_in to the file descriptor fd_out, where one
	 * of the descriptors must refer to a pipe.
	 *
	 * Technically, the following implementation is unsound for
	 * programs that splice with stdin/stdout/stderr and have
	 * output redirected during replay.  But, *crickets*.
	 */
	SYS_REC0(splice)

	/**
	 * mode_t umask(mode_t mask);
	 * umask()  sets  the  calling  process's file mode creation mask (umask) to mask & 0777
	 * (i.e., only the file permission bits of mask are used), and returns the previous value of the mask.
	 *
	 */
	SYS_REC0(umask)

	/**
	 * int unlink(const char *path);
	 *
	 * The unlink() function shall remove a link to a file. If path names a symbolic link, unlink()
	 * shall remove the symbolic link named by path and shall not affect any file or directory named
	 * by the contents of the symbolic link. Otherwise, unlink() shall remove the link named by the
	 * pathname pointed to by path and shall decrement the link count of the file referenced by the link.
	 *
	 */
	SYS_REC0(unlink)

	/**
	 * int unlinkat(int dirfd, const char *pathname, int flags)
	 *
	 * The unlinkat() system call operates in exactly the same way as either unlink(2) or
	 * rmdir(2) (depending on whether or not flags includes the AT_REMOVEDIR flag) except for the
	 * differences described in this manual page.
	 */
	SYS_REC0(unlinkat)

	/**
	 * int utimes(const char *filename, const struct timeval times[2])
	 *
	 * The utime() system call changes the access and modification times of the inode specified by
	 * filename to the actime and modtime fields of times respectively.
	 *
	 */
	SYS_REC1(utimes, 2*sizeof(struct timeval), (void*)regs.ecx);

	/**
	 * pid_t vfork(void);
	 *
	 * vfork - create a child process and block parent
	 */
	SYS_REC0(vfork)

	/**
	 * pid_t waitpid(pid_t pid, int *status, int options);
	 *
	 * The waitpid() system call suspends execution of the calling process until
	 * a child specified by pid argument has changed state.  By default, waitpid()
	 * waits only for terminated children, but this behavior  is  modifiable  via
	 * the options argument, as described below....
	 *
	 */
	/**
	 * pid_t wait4(pid_t pid, int *status, int options, struct rusage *rusage);
	 *
	 * The  wait3()  and wait4() system calls are similar to waitpid(2), but
	 * additionally return resource usage information about the child in the
	 * structure pointed to by rusage.
	 */
	case SYS_waitpid:
	case SYS_wait4:	{
		struct rusage* rusage = pop_arg_ptr(t);
		int* status = pop_arg_ptr(t);
		void* iter;
		void* data = start_restoring_scratch(t, &iter);

		if (status) {
			restore_and_record_arg_buf(t,
						   sizeof(*status), status,
						   &iter);
			regs.ecx = (uintptr_t)status;
		} else {
			record_noop_data(t);
		}
		if (rusage) {
			restore_and_record_arg_buf(t,
						   sizeof(*rusage), rusage,
						   &iter);
			regs.esi = (uintptr_t)rusage;
		} else if (SYS_wait4 == syscall) {
			record_noop_data(t);
		}
		write_child_registers(tid, &regs);

		finish_restoring_scratch(t, iter, &data);
	}

	/**
	 * ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
	 * The writev() function writes iovcnt buffers of data described by iov
	 * to the file associated with the file descriptor fd ("gather output").
	 */
	SYS_REC0(writev)

	case SYS_rrcall_init_syscall_buffer:
		init_syscall_buffer(t, NULL, SHARE_DESCHED_EVENT_FD);
		break;

	default:
		print_register_file_tid(tid);
		fatal("Unknown syscall %s(%d)", syscallname(syscall), syscall);
		break;		/* not reached */
	}
}
