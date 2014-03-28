/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

//#define DEBUGTAG "ProcessSyscallRec"

#include "record_syscall.h"

#include <arpa/inet.h>
#include <asm/ldt.h>
#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/ethtool.h>
#include <linux/futex.h>
#include <linux/if.h>
#include <linux/ipc.h>
#include <linux/msg.h>
#include <linux/net.h>
#include <linux/prctl.h>
#include <linux/sem.h>
#include <linux/shm.h>
#include <linux/sockios.h>
#include <linux/wireless.h>
#include <poll.h>
#include <sched.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
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
#include <termios.h>

#include <limits>
#include <utility>

#include <rr/rr.h>

#include "preload/syscall_buffer.h"

#include "dbg.h"
#include "drm.h"
#include "recorder.h"		// for terminate_recording()
#include "recorder_sched.h"
#include "task.h"
#include "trace.h"
#include "util.h"

using namespace std;

/**
 * The parameters that are packaged up for the ACCEPT and ACCEPT4
 * socketcalls.
 */
struct accept_args {
	long sockfd;
	struct sockaddr* addr;
	socklen_t* addrlen;
};
struct accept4_args {
	struct accept_args _;
	long flags;
};

/**
 *  Some ipc calls require 7 params, so two of them are stashed into
 *  one of these structs and a pointer to this is passed instead.
 */
struct ipc_kludge_args {
	void* msgbuf;
	long msgtype;
};

/** Params packaged up for RECVFROM socketcalls. */
struct recvfrom_args {
	long sockfd;
	void* buf;
	size_t len;
	long flags;
	struct sockaddr* src_addr;
	socklen_t* addrlen;
};

void rec_before_record_syscall_entry(Task* t, int syscallno)
{
	if (SYS_write != syscallno) {
		return;
	}
	int fd = t->regs().ebx;
	if (RR_MAGIC_SAVE_DATA_FD != fd) {
		return;
	}
	void* buf = (void*)t->regs().ecx;
	size_t len = t->regs().edx;

	assert_exec(t, buf, "Can't save a null buffer");

	record_child_data(t, len, buf);
}

/**
 * Read the socketcall args pushed by |t| as part of the syscall in
 * |regs| into the |args| outparam.  Also store the address of the
 * socketcall args into |*argsp|.
 */
template<typename T>
void read_socketcall_args(Task* t, long** argsp, T* args)
{
	void* p = (void*)t->regs().ecx;
	t->read_mem(p, args);
	*argsp = (long*)p;
}

/**
 * Erase any scratch pointer initialization done for |t| and leave
 * the state bits ready to be initialized again.
 */
static void reset_scratch_pointers(Task* t)
{
	assert(t->ev().type == EV_SYSCALL);

	FIXEDSTACK_CLEAR(&t->ev().syscall.saved_args);
	t->ev().syscall.tmp_data_ptr = t->scratch_ptr;
	t->ev().syscall.tmp_data_num_bytes = -1;
}

/**
 * Record a tracee argument pointer that (most likely) was replaced by
 * a pointer into scratch memory.  |argp| can have any value,
 * including NULL.  It must be fetched by calling |pop_arg_ptr()|
 * during processing syscall results, and in reverse order of calls to
 * |push*()|.
 */
static void push_arg_ptr(Task* t, void* argp)
{
	FIXEDSTACK_PUSH(&t->ev().syscall.saved_args, argp);
}

/**
 * Reset scratch state for |t|, because scratch can't be used for
 * |event|.  Log a warning as well.
 */
static int abort_scratch(Task* t, const char* event)
{
	int num_bytes = t->ev().syscall.tmp_data_num_bytes;

	assert(t->ev().syscall.tmp_data_ptr == t->scratch_ptr);

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
static int can_use_scratch(Task* t, byte* scratch_end)
{
	byte* scratch_start = (byte*)t->scratch_ptr;

	assert(t->ev().syscall.tmp_data_ptr == t->scratch_ptr);

	t->ev().syscall.tmp_data_num_bytes = (scratch_end - scratch_start);
	return (0 <= t->ev().syscall.tmp_data_num_bytes
		&& t->ev().syscall.tmp_data_num_bytes <= t->scratch_size);
}

/**
 * Return nonzero if it's OK to context-switch away from |t| for its
 * ipc call.  If so, prepare any required scratch buffers for |t|.
 */
static int prepare_ipc(Task* t, int would_need_scratch)
{
	int call = t->regs().ebx;
	byte* scratch = would_need_scratch ?
			(byte*)t->ev().syscall.tmp_data_ptr : nullptr;

	assert(!t->desched_rec());

	switch (call) {
	case MSGRCV: {
		if (!would_need_scratch) {
			return 1;
		}
		size_t msgsize = t->regs().edx;
		struct ipc_kludge_args kludge;
		void* child_kludge = (void*)t->regs().edi;
		t->read_mem(child_kludge, &kludge);

		push_arg_ptr(t, kludge.msgbuf);
		kludge.msgbuf = scratch;
		scratch += msgsize;
		if (!can_use_scratch(t, scratch)) {
			return abort_scratch(t, "msgrcv");
		}
		t->write_mem(child_kludge, kludge);
		return 1;
	}
	case MSGSND:
		return 1;
	default:
		return 0;
	}
}

/**
 * Read the msg_iov array from |msg| into |iovs|, which must be sized
 * appropriately.  Return the total number of bytes comprising |iovs|.
 */
static ssize_t read_iovs(Task* t, const struct msghdr& msg,
			 struct iovec* iovs)
{
	size_t num_iov_bytes = msg.msg_iovlen * sizeof(*iovs);
	t->read_bytes_helper(msg.msg_iov, num_iov_bytes, (byte*)iovs);
	return num_iov_bytes;
}

/**
 * Initialize any necessary state to execute the socketcall that |t|
 * is stopped at, for example replacing tracee args with pointers into
 * scratch memory if necessary.
 */
static int prepare_socketcall(Task* t, int would_need_scratch)
{
	byte* scratch = would_need_scratch ?
			(byte*)t->ev().syscall.tmp_data_ptr : nullptr;
	long* argsp;
	void* tmpargsp;
	struct user_regs_struct r = t->regs();

	assert(!t->desched_rec());

	/* int socketcall(int call, unsigned long *args) {
	 * 		long a[6];
	 * 		copy_from_user(a,args);
	 *  	sys_recv(a0, (void __user *)a1, a[2], a[3]);
	 *  }
	 *
	 *  (from http://lxr.linux.no/#linux+v3.6.3/net/socket.c#L2354)
	 */
	int call = r.ebx;
	switch (call) {
	/* ssize_t recv([int sockfd, void *buf, size_t len, int flags]) */
	case SYS_RECV: {
		struct { long words[4]; } args;

		if (!would_need_scratch) {
			return 1;
		}
		read_socketcall_args(t, &argsp, &args);
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
		r.ecx = (uintptr_t)(tmpargsp = scratch);
		scratch += sizeof(args);
		/* The |buf| pointer. */
		push_arg_ptr(t, (void*)args.words[1]);
		args.words[1] = (uintptr_t)scratch;
		scratch += args.words[2]/*len*/;
		if (!can_use_scratch(t, scratch)) {
			return abort_scratch(t, "recv");
		}

		t->write_mem(tmpargsp, args);
		t->set_regs(r);
		return 1;
	}

	/* int accept([int sockfd, struct sockaddr *addr, socklen_t *addrlen]) */
	/* int accept4([int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags]) */
	case SYS_ACCEPT:
	case SYS_ACCEPT4: {
		if (!would_need_scratch) {
			return 1;
		}
		struct user_regs_struct r = t->regs();
		void* argsp = (void*)r.ecx;
		struct accept4_args args;
		if (SYS_ACCEPT == call) {
			t->read_mem(argsp, &args._);
		} else {
			t->read_mem(argsp, &args);
		}

		socklen_t addrlen;
		t->read_mem(args._.addrlen, &addrlen);

		// We use the same basic scheme here as for RECV
		// above.  For accept() though, there are two
		// (in)outparams: |addr| and |addrlen|.  |*addrlen| is
		// the total size of |addr|, so we reserve that much
		// space for it.  |*addrlen| is set to the size of the
		// returned sockaddr, so we reserve space for
		// |addrlen| too.

		// Reserve space for scratch socketcall args.
		push_arg_ptr(t, argsp);
		void* tmpargsp = scratch;
		r.ecx = (uintptr_t)tmpargsp;
		scratch += (SYS_ACCEPT == call) ?
			   sizeof(args._) : sizeof(args);

		push_arg_ptr(t, args._.addrlen);
		args._.addrlen = (socklen_t*)scratch;
		scratch += sizeof(*args._.addrlen);

		byte* src = (byte*)args._.addr;
		push_arg_ptr(t, src);
		args._.addr = (struct sockaddr*)scratch;
		scratch += addrlen;
		if (!can_use_scratch(t, scratch)) {
			return abort_scratch(t, "accept");
		}

		if (SYS_ACCEPT == call) {
			t->write_mem(tmpargsp, args._);
		} else {
			t->write_mem(tmpargsp, args);
		}
		t->write_mem(args._.addrlen, addrlen);
		t->set_regs(r);
		return 1;
	}
	case SYS_RECVFROM: {
		if (!would_need_scratch) {
			return 1;
		}
		struct user_regs_struct r = t->regs();
		void* argsp = (void*)r.ecx;
		struct recvfrom_args args;
		t->read_mem(argsp, &args);

		// Reserve space for scratch socketcall args.
		push_arg_ptr(t, argsp);
		void* tmpargsp = scratch;
		r.ecx = (uintptr_t)tmpargsp;
		scratch += sizeof(args);

		push_arg_ptr(t, args.buf);
		args.buf = scratch;
		scratch += args.len;

		socklen_t addrlen;
		if (args.src_addr) {
			t->read_mem(args.addrlen, &addrlen);

			push_arg_ptr(t, args.addrlen);
			args.addrlen = (socklen_t*)scratch;
			scratch += sizeof(*args.addrlen);

			push_arg_ptr(t, args.src_addr);
			args.src_addr = (struct sockaddr*)scratch;
			scratch += addrlen;
		} else {
			push_arg_ptr(t, nullptr);
			push_arg_ptr(t, nullptr);
		}
		if (!can_use_scratch(t, scratch)) {
			return abort_scratch(t, "recvfrom");
		}

		t->write_mem(tmpargsp, args);
		if (args.addrlen) {
			t->write_mem(args.addrlen, addrlen);
		}
		t->set_regs(r);
		return 1;
	}
	case SYS_RECVMSG: {
		struct user_regs_struct r = t->regs();
		void* argsp = (void*)r.ecx;
		struct recvmsg_args args;
		t->read_mem(argsp, &args);
		if (args.flags & MSG_DONTWAIT) {
			return 0;
		}
		if (!would_need_scratch) {
			return 1;
		}
		struct msghdr msg;
		t->read_mem(args.msg, &msg);

		struct msghdr tmpmsg = msg;
		// Reserve space for scratch socketcall args.
		push_arg_ptr(t, argsp);
		void* tmpargsp = scratch;
		scratch += sizeof(args);
		r.ecx = (uintptr_t)tmpargsp;

		byte* scratch_msg = scratch;
		scratch += sizeof(msg);

		if (msg.msg_name) {
			tmpmsg.msg_name = scratch;
			scratch += tmpmsg.msg_namelen;
		}

		struct iovec iovs[msg.msg_iovlen];
		ssize_t num_iov_bytes = read_iovs(t, msg, iovs);
		tmpmsg.msg_iov = (struct iovec*)scratch;
		scratch += num_iov_bytes;

		struct iovec tmpiovs[tmpmsg.msg_iovlen];
		memcpy(tmpiovs, iovs, num_iov_bytes);
		for (size_t i = 0; i < msg.msg_iovlen; ++i) {
			struct iovec& tmpiov = tmpiovs[i];
			tmpiov.iov_base = scratch;
			scratch += tmpiov.iov_len;
		}

		if (msg.msg_control) {
			tmpmsg.msg_control = scratch;
			scratch += tmpmsg.msg_controllen;
		}

		if (!can_use_scratch(t, scratch)) {
			return abort_scratch(t, "recvfrom");
		}

		args.msg = (struct msghdr*)scratch_msg;
		t->write_mem(tmpargsp, args);
		t->set_regs(r);

		t->write_mem(args.msg, tmpmsg);
		t->write_bytes_helper(tmpmsg.msg_iov, num_iov_bytes,
				      (const byte*)tmpiovs);
		for (size_t i = 0; i < tmpmsg.msg_iovlen; ++i) {
			const struct iovec& iov = iovs[i];
			const struct iovec& tmpiov = tmpiovs[i];
			t->remote_memcpy(tmpiov.iov_base, iov.iov_base,
					 tmpiov.iov_len);
		}
		if (msg.msg_control) {
			t->remote_memcpy(tmpmsg.msg_control, msg.msg_control,
					 tmpmsg.msg_controllen);
		}
		return 1;
	}
	case SYS_SENDMSG: {
		struct user_regs_struct r = t->regs();
		void* argsp = (void*)r.ecx;
		struct recvmsg_args args;
		t->read_mem(argsp, &args);
		return !(args.flags & MSG_DONTWAIT);
	}
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
static int set_up_scratch_for_syscallbuf(Task* t, int syscallno)
{
	const struct syscallbuf_record* rec = t->desched_rec();

	assert(rec);
	assert_exec(t, syscallno == rec->syscallno, 
		    "Syscallbuf records syscall %s, but expecting %s",
		    syscallname(rec->syscallno), syscallname(syscallno));

	reset_scratch_pointers(t);
	t->ev().syscall.tmp_data_ptr =
		(byte*)t->syscallbuf_child +
		(rec->extra_data - (byte*)t->syscallbuf_hdr);
	/* |rec->size| is the entire record including extra data; we
	 * just care about the extra data here. */
	t->ev().syscall.tmp_data_num_bytes = rec->size - sizeof(*rec);
	return 1;
}

/**
 * Prepare |futex| for a FUTEX_LOCK_PI call by |t|.  See
 * |rec_process_syscall()| for a description of |kernel_sync_addr| and
 * |sync_val|.
 *
 * The key to this scheme is us proving that syncing on the
 * FUTEX_WAITERS write to the futex (i) isn't racy; (ii) is
 * deterministically replayable.  The sequence of relevant events is
 *
 *  1. Thread A acquires futex f.
 *  2. Thread B tries to fast-path acquire f in userspace and fails.
 *  3. Thread B invokes syscall(SYS_futex, f, FUTEX_LOCK_PI) and
 *     ptrace-traps to rr.
 *  4. rr resumes execution of the futex syscall.
 *  5. Eventually, the kernel does a compare-and-swap on the futex
 *     value to try to acquire it on B's behalf.  If it fails, then
 *     the futex transitions into a "contended" state and the kernel
 *     does some bookkeeping that's not relevant here.
 *  6. The kernel atomically sets the FUTEX_WAITERS bit on the futex.
 *
 * There are no data hazards between (1)-(4), because they merely
 * consist of memory operations and syscall entry.  The problem begins
 * at (4)-(5).
 *
 * Between (4)-(5), the kernel would read and write the futex value
 * behind rr's back.  That means there are write/write and read/write
 * hazards going both directions that rr can't record and replay
 * deterministically.
 *
 * rr can detect that these data hazards will arise at the ptrace-trap
 * in (3) by examining the value of f (not B's tid and doesn't have
 * the FUTEX_WAITERS bit set).  But is even /that check/ racy?  No; if
 * the mutex is already acquired by tracee A, then we know A won't run
 * concurrently.  We also know that no other tracees are running
 * /userspace/ code concurrently.  Can the kernel mutate f behind rr's
 * back though?
 *
 * No.  First, rr executes FUTEX_UNLOCK_PI atomically, so it can't be
 * running.  Second, another FUTEX_LOCK_PI call can't race with this,
 * because (i) this is the first time rr has detected that the futex
 * will be contended; (ii) the initial acquisition by A must have been
 * made in userspace.  (And, as mentioned above, A"s acquisition can't
 * race with this.)
 *
 * So the check isn't racy.  Now, let's have rr wait until it sees f
 * updated with the FUTEX_WAITERS bit by the kernel in (6).  Waiting
 * for the FUTEX_WAITERS bit is inherently racy of course, but it's
 * atomic and sequentially consistent wrt tracee execution.  When rr
 * detects the FUTEX_WAITERS bit, the kernel will no longer attempt to
 * modify f.  So can rr replay this bit-set deterministically?
 *
 * Yes, by another version of the argument above.  No other tracees
 * can be racing with the bit-set.  And no other kernel operations can
 * be racing with it either (nothing new has happened with f since
 * (4), remember).
 *
 * So rr (i) waits for the kernel's bit-set in recording and (ii) sets
 * the bit itself at (3) during replay, and this is deterministic.
 */
static bool prep_futex_lock_pi(Task* t, byte* futex,
			       void** kernel_sync_addr, uint32_t* sync_val)
{
	if (is_now_contended_pi_futex(t, futex, sync_val)) {
		*kernel_sync_addr = futex;
	}
	return true;
}

int rec_prepare_syscall(Task* t, void** kernel_sync_addr, uint32_t* sync_val)
{
	int syscallno = t->ev().syscall.no;
	/* If we are called again due to a restart_syscall, we musn't
	 * redirect to scratch again as we will lose the original
	 * addresses values. */
	bool restart = (syscallno == SYS_restart_syscall);
	int would_need_scratch;
	byte* scratch = NULL;

	if (t->desched_rec()) {
		return set_up_scratch_for_syscallbuf(t, syscallno);
	}

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
		scratch = (byte*)t->ev().syscall.tmp_data_ptr;
	}

	switch (syscallno) {
	case SYS_splice: {
		struct user_regs_struct r = t->regs();
		loff_t* off_in = (loff_t*)r.ecx;
		loff_t* off_out = (loff_t*)r.esi;

		if (!would_need_scratch) {
			return 1;
		}

		push_arg_ptr(t, off_in);
		if (off_in) {
			loff_t* off_in2 = (loff_t*)scratch;
			scratch += sizeof(*off_in2);
			t->remote_memcpy(off_in2, off_in, sizeof(*off_in2));
       			r.ecx = (uintptr_t)off_in2;
		}
		push_arg_ptr(t, off_out);
		if (off_out) {
			loff_t* off_out2 = (loff_t*)scratch;
			scratch += sizeof(*off_out2);
			t->remote_memcpy(off_out2, off_out, sizeof(*off_out2));
       			r.esi = (uintptr_t)off_out2;
		}
		if (!can_use_scratch(t, scratch)) {
			return abort_scratch(t, syscallname(syscallno));
		}

		t->set_regs(r);
		return 1;
	}

	case SYS_clone: {
		unsigned long flags = t->regs().ebx;
		push_arg_ptr(t, (void*)(uintptr_t)flags);
		if (flags & CLONE_UNTRACED) {
			struct user_regs_struct r = t->regs();
			// We can't let tracees clone untraced tasks,
			// because they can create nondeterminism that
			// we can't replay.  So unset the UNTRACED bit
			// and then cover our tracks on exit from
			// clone().
			r.ebx = flags & ~CLONE_UNTRACED;
			t->set_regs(r);
		}
		return 0;
	}

	case SYS_exit:
		destroy_buffers(t, (DESTROY_ALREADY_AT_EXIT_SYSCALL |
				    DESTROY_NEED_EXIT_SYSCALL_RESTART));
		return 0;

	case SYS_fcntl64:
		switch (t->regs().ecx) {
		case F_SETLKW:
		case F_SETLKW64:
			// SETLKW blocks, but doesn't write any
			// outparam data to the |struct flock|
			// argument, so no need for scratch.
			return 1;
		default:
			return 0;
		}

	/* int futex(int *uaddr, int op, int val, const struct timespec *timeout, int *uaddr2, int val3); */
	case SYS_futex:
		switch (t->regs().ecx & FUTEX_CMD_MASK) {
		case FUTEX_LOCK_PI:
			return prep_futex_lock_pi(t, (byte*)t->regs().ebx,
						  kernel_sync_addr, sync_val);
		case FUTEX_WAIT:
		case FUTEX_WAIT_BITSET:
		case FUTEX_WAIT_REQUEUE_PI:
			return 1;
		default:
			return 0;
		}

	case SYS_ipc:
		return prepare_ipc(t, would_need_scratch);

	case SYS_socketcall:
		return prepare_socketcall(t, would_need_scratch);

	case SYS__newselect:
		return 1;

	/* ssize_t read(int fd, void *buf, size_t count); */
	case SYS_read: {
		if (!would_need_scratch) {
			return 1;
		}
		struct user_regs_struct r =  t->regs();

		push_arg_ptr(t, (void*)r.ecx);
		r.ecx = (uintptr_t)scratch;
		scratch += r.edx/*count*/;

		if (!can_use_scratch(t, scratch)) {
			return abort_scratch(t, syscallname(syscallno));
		}

		t->set_regs(r);
		return 1;
	}

	case SYS_write:
	case SYS_writev:
		maybe_mark_stdio_write(t, t->regs().ebx);
		return 1;

	/* pid_t waitpid(pid_t pid, int *status, int options); */
	/* pid_t wait4(pid_t pid, int *status, int options, struct rusage *rusage); */
	case SYS_waitpid:
	case SYS_wait4: {
		struct user_regs_struct r = t->regs();
		int* status = (int*)r.ecx;
		struct rusage* rusage = (SYS_wait4 == syscallno) ?
					(struct rusage*)r.esi : NULL;

		if (!would_need_scratch) {
			return 1;
		}
		push_arg_ptr(t, status);
		if (status) {
			r.ecx = (uintptr_t)scratch;
			scratch += sizeof(*status);
		}
		push_arg_ptr(t, rusage);
		if (rusage) {
			r.esi = (uintptr_t)scratch;
			scratch += sizeof(*rusage);
		}

		if (!can_use_scratch(t, scratch)) {
			return abort_scratch(t, syscallname(syscallno));
		}

		t->set_regs(r);
		return 1;
	}

	case SYS_waitid: {
		if (!would_need_scratch) {
			return 1;
		}

		struct user_regs_struct r = t->regs();
		siginfo_t* infop = (siginfo_t*)r.edx;
		push_arg_ptr(t, infop);
		if (infop) {
			r.edx = (uintptr_t)scratch;
			scratch += sizeof(*infop);
		}

		if (!can_use_scratch(t, scratch)) {
			return abort_scratch(t, syscallname(syscallno));
		}

		t->set_regs(r);
		return 1;
	}

	case SYS_pause:
		return 1;

	/* int poll(struct pollfd *fds, nfds_t nfds, int timeout) */
	/* int ppoll(struct pollfd *fds, nfds_t nfds,
	 *           const struct timespec *timeout_ts,
	 *           const sigset_t *sigmask); */
	case SYS_poll:
	case SYS_ppoll: {
		struct user_regs_struct r = t->regs();
		struct pollfd* fds = (struct pollfd*)r.ebx;
		struct pollfd* fds2 = (struct pollfd*)scratch;
		nfds_t nfds = r.ecx;

		if (!would_need_scratch) {
			return 1;
		}
		/* XXX fds can be NULL, right? */
		push_arg_ptr(t, fds);
		r.ebx = (uintptr_t)fds2;
		scratch += nfds * sizeof(*fds);

		if (!can_use_scratch(t, scratch)) {
			return abort_scratch(t, syscallname(syscallno));
		}
		/* |fds| is an inout param, so we need to copy over
		 * the source data. */
		t->remote_memcpy(fds2, fds, nfds * sizeof(*fds));
		t->set_regs(r);
		return 1;
	}

	/* int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5); */
	case SYS_prctl: {
		/* TODO: many of these prctls are not blocking. */
		if (!would_need_scratch) {
			return 1;
		}
		struct user_regs_struct r = t->regs();
		switch (r.ebx) {
		case PR_GET_ENDIAN:
		case PR_GET_FPEMU:
		case PR_GET_FPEXC:
		case PR_GET_PDEATHSIG:
		case PR_GET_TSC:
		case PR_GET_UNALIGN: {
			int* outparam = (int*)r.ecx;

			push_arg_ptr(t, outparam);
			r.ecx = (uintptr_t)scratch;
			scratch += sizeof(*outparam);

			if (!can_use_scratch(t, scratch)) {
				return abort_scratch(t,
						     syscallname(syscallno));
			}

			t->set_regs(r);
			return 1;
		}
		case PR_GET_NAME:
		case PR_SET_NAME:
			return 0;

		default:
			/* TODO: there are many more prctls with
			 * outparams ... */
			return 1;
		}
		fatal("Not reached");
	}

	/* int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout); */
	case SYS_epoll_wait: {
		if (!would_need_scratch) {
			return 1;
		}

		struct user_regs_struct r = t->regs();
		struct epoll_event* events = (struct epoll_event*)r.ecx;
		int maxevents = r.edx;

		push_arg_ptr(t, events);
		r.ecx = (uintptr_t)scratch;
		scratch += maxevents * sizeof(*events);

		if (!can_use_scratch(t, scratch)) {
			return abort_scratch(t, syscallname(syscallno));
		}

		/* (Unlike poll(), the |events| param is a pure
		 * outparam, no copy-over needed.) */
		t->set_regs(r);
		return 1;
	}

	case SYS_ptrace:
		fprintf(stderr,
"\n"
"rr: internal recorder error:\n"
"  ptrace() is not yet supported.  We need to go deeper.\n"
"\n"
"  Your trace is being synced and will be available for replay when\n"
"  this process exits.\n"
			);
		terminate_recording(t);
		fatal("Not reached");
		return 0;


	case SYS_epoll_pwait:
		fatal("Unhandled syscall %s", syscallname(syscallno));
		return 1;

	/* The following two syscalls enable context switching not for
	 * liveness/correctness reasons, but rather because if we
	 * didn't context-switch away, rr might end up busy-waiting
	 * needlessly.  In addition, albeit far less likely, the
	 * client program may have carefully optimized its own context
	 * switching and we should take the hint. */

	/* int nanosleep(const struct timespec *req, struct timespec *rem); */
	case SYS_nanosleep: {
		if (!would_need_scratch) {
			return 1;
		}

		struct user_regs_struct r= t->regs();
		struct timespec* rem = (struct timespec*)r.ecx;
		push_arg_ptr(t, rem);
		if (rem) {
       			r.ecx = (uintptr_t)scratch;
			scratch += sizeof(*rem);
		}

		if (!can_use_scratch(t, scratch)) {
			return abort_scratch(t, syscallname(syscallno));
		}

		t->set_regs(r);
		return 1;
	}

	case SYS_sched_yield:
		// Force |t| to be context-switched if another thread
		// of equal or higher priority is available.  We set
		// the counter to INT_MAX / 2 because various other
		// irrelevant events intervening between now and
		// scheduling may increment t's event counter, and we
		// don't want it to overflow.
		t->succ_event_counter = numeric_limits<int>::max() / 2;
		// We're just pretending that t is blocked.  The next
		// time its scheduling slot opens up, it's OK to
		// blocking-waitpid on t to see its status change.
		t->pseudo_blocked = 1;
		return 1;

	case SYS_recvmmsg:
	case SYS_sendmmsg:
		// TODO: these can block.
		return abort_scratch(t, syscallname(syscallno));

	default:
		return 0;
	}
}

/**
 * Write a trace data record that when replayed will be a no-op.  This
 * is used to avoid having special cases in replay code for failed
 * syscalls, e.g.
 */
static void record_noop_data(Task* t)
{
	record_parent_data(t, 0, NULL, NULL);
}

void rec_prepare_restart_syscall(Task* t)
{
	int syscallno = t->ev().syscall.no;
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
		struct timespec* rem = (struct timespec*)
				       *FIXEDSTACK_TOP(&t->ev().syscall.saved_args);
		struct timespec* rem2 = (struct timespec*)t->regs().ecx;

		if (rem) {
			t->remote_memcpy(rem, rem2, sizeof(*rem));
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

static void init_scratch_memory(Task *t)
{
	const int scratch_size = 512 * page_size();
	/* initialize the scratchpad for blocking system calls */
	struct current_state_buffer state;
	prepare_remote_syscalls(t, &state);

	size_t sz = scratch_size;
	// The PROT_EXEC looks scary, and it is, but it's to prevent
	// this region from being coalesced with another anonymous
	// segment mapped just after this one.  If we named this
	// segment, we could remove this hack.
	int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
	int flags = MAP_PRIVATE | MAP_ANONYMOUS;
	int fd = -1;
	off64_t offset_pages = 0;

	t->scratch_ptr = (void*)remote_syscall6(t, &state, SYS_mmap2,
						0, sz, prot, flags,
						fd, offset_pages);
	t->scratch_size = scratch_size;
	finish_remote_syscalls(t, &state);

	// record this mmap for the replay
	struct user_regs_struct r = t->regs();
	int eax = r.eax;
	r.eax = (uintptr_t)t->scratch_ptr;
	t->set_regs(r);

	struct mmapped_file file = {0};
	file.time = get_global_time();
	file.tid = t->tid;
	file.start = t->scratch_ptr;
	file.end = (byte*)t->scratch_ptr + scratch_size;
	sprintf(file.filename,"scratch for thread %d",t->tid);
	record_mmapped_file_stats(&file);

	r.eax = eax;
	t->set_regs(r);

	t->vm()->map(t->scratch_ptr, sz, prot, flags,
		     page_size() * offset_pages,
		     MappableResource::scratch(t->rec_tid));
}

/**
 * Read the scratch data written by the kernel in the syscall and
 * return an opaque handle to it.  The outparam |iter| can be used to
 * copy the read memory.
 *
 * The returned opaque handle must be passed to
 * |finish_restoring_scratch()|.
 */
static void* start_restoring_scratch(Task* t, byte** iter)
{
	// TODO: manage this in Task.
	void* scratch = t->ev().syscall.tmp_data_ptr;
	ssize_t num_bytes = t->ev().syscall.tmp_data_num_bytes;

	assert(num_bytes >= 0);

	byte* data = (byte*)malloc(num_bytes);
	t->read_bytes_helper(scratch, num_bytes, data);
	return *iter = data;
}

/**
 * Return nonzero if tracee pointers were saved while preparing for
 * the syscall |t->ev|.
 */
static int has_saved_arg_ptrs(Task* t)
{
	return !FIXEDSTACK_EMPTY(&t->ev().syscall.saved_args);
}

/**
 * Return the replaced tracee argument pointer saved by the matching
 * call to |push_arg_ptr()|.
 */
template<typename T>
static T* pop_arg_ptr(Task* t)
{
	void* arg = FIXEDSTACK_POP(&t->ev().syscall.saved_args);
	return static_cast<T*>(arg);
}

/**
 * Write |num_bytes| of data from |parent_data_iter| to |child_addr|.
 * Record the written data so that it can be restored during replay of
 * |syscallno|.
 */
static void restore_and_record_arg_buf(Task* t,
				       size_t num_bytes, void* child_addr,
				       byte** parent_data_iter)
{
	// TODO: move scratch-arg tracking into Task
	byte* parent_data = *parent_data_iter;
	t->write_bytes_helper(child_addr, num_bytes, parent_data);
	record_parent_data(t, num_bytes, child_addr, parent_data);
	*parent_data_iter += num_bytes;
}

template<typename T>
static void restore_and_record_arg(Task* t,  T* child_arg,
				   byte** parent_data_iter)
{
	return restore_and_record_arg_buf(t, sizeof(*child_arg), child_arg,
					  parent_data_iter);
}

/**
 * Finish the sequence of operations begun by the most recent
 * |start_restoring_scratch()| and check that no mistakes were made.
 * |*data| must be the opaque handle returned by |start_*()|.
 *
 * Don't call this directly; use one of the helpers below.
 */
enum { NO_SLACK = 0, ALLOW_SLACK = 1 };
static void finish_restoring_scratch_slack(Task* t, byte* iter, void** datap,
					   int slack)
{
	byte* data = (byte*)*datap;
	ssize_t consumed = (iter - data);
	ssize_t diff = t->ev().syscall.tmp_data_num_bytes - consumed;

	assert(t->ev().syscall.tmp_data_ptr == t->scratch_ptr);
	assert_exec(t, !diff || (slack && diff > 0),
		    "Saved %d bytes of scratch memory but consumed %d",
		    t->ev().syscall.tmp_data_num_bytes, consumed);
	if (slack) {
		debug("Left %d bytes unconsumed in scratch", diff);
	}
	assert_exec(t, FIXEDSTACK_EMPTY(&t->ev().syscall.saved_args),
		    "Under-consumed saved arg pointers");

	free(data);
}

/**
 * Like above, but require that all saved scratch data was consumed.
 */
static void finish_restoring_scratch(Task* t, byte* iter, void** data)
{
	return finish_restoring_scratch_slack(t, iter, data, NO_SLACK);
}

/**
 * Like above, but allow some saved scratch data to remain unconsumed,
 * for example if a buffer wasn't filled entirely.
 */
static void finish_restoring_some_scratch(Task* t, byte* iter, void** data)
{
	return finish_restoring_scratch_slack(t, iter, data, ALLOW_SLACK);
}

static void process_execve(Task* t)
{
	// XXX what does this signifiy?
	if (t->regs().ebx != 0) {
		return;
	}

	t->post_exec();

	long* stack_ptr = (long*)t->regs().esp;

	/* start_stack points to argc - iterate over argv pointers */

	/* FIXME: there are special cases, like when recording gcc,
	 *        where the esp does not point to argc. For example,
	 *        it may point to &argc.
	 */
//	long* argc = (long*)t->read_word((byte*)stack_ptr);
//	stack_ptr += *argc + 1;
	long argc = t->read_word(stack_ptr);
	stack_ptr += argc + 1;	

	//unsigned long* null_ptr = read_child_data(t, sizeof(void*), stack_ptr);
	//assert(*null_ptr == 0);
	long null_ptr = t->read_word(stack_ptr);
	assert(null_ptr == 0);
	stack_ptr++;

	/* should now point to envp (pointer to environment strings) */
	while (0 != t->read_word(stack_ptr)) {
		stack_ptr++;
	}
	stack_ptr++;

	/* should now point to ELF Auxiliary Table */
	const long elf_aux[] = {
		AT_SYSINFO, AT_SYSINFO_EHDR, AT_HWCAP, AT_PAGESZ, AT_CLKTCK,
		AT_PHDR, AT_PHENT, AT_PHNUM, AT_BASE, AT_FLAGS, AT_ENTRY,
		AT_UID, AT_EUID, AT_GID, AT_EGID,
		AT_SECURE
	};

	struct ElfEntry { long key; long value; };
	union {
		ElfEntry entries[ALEN(elf_aux)];
		byte bytes[sizeof(entries)];
	} table;
	t->read_bytes(stack_ptr, table.bytes);
	stack_ptr += 2 * ALEN(elf_aux);

	for (int i = 0; i < ssize_t(ALEN(elf_aux)); ++i) {
		long expected_field = elf_aux[i];
		const ElfEntry& entry = table.entries[i];
		assert_exec(t, expected_field == entry.key,
			    "Elf aux entry %d should be 0x%lx, but is 0x%lx",
			    i, expected_field, entry.key);
	}

	long at_random = t->read_word(stack_ptr);
	stack_ptr++;
	assert_exec(t, AT_RANDOM == at_random,
		    "ELF item should be 0x%x, but is 0x%lx",
		    AT_RANDOM, at_random);

	void* rand_addr = (void*)t->read_word(stack_ptr);
	// XXX where does the magic number come from?
	record_child_data(t, 16, rand_addr);

	init_scratch_memory(t);
}

static void record_ioctl_data(Task *t, ssize_t num_bytes)
{
	void* param = (void*)t->regs().edx;
	record_child_data(t, num_bytes, param);
}

/**
 * Record.the page above the top of |t|'s stack.  The SIOC* ioctls
 * have been observed to write beyond the end of tracees' stacks, as
 * if they had allocated scratch space for themselves.  All we can do
 * for now is try to record the scratch data.
 */
static void record_scratch_stack_page(Task* t)
{
	record_child_data(t, page_size(), (byte*)t->sp() - page_size());
}

static void process_ioctl(Task *t, int request)
{
	int type = _IOC_TYPE(request);
	int nr = _IOC_NR(request);
	int dir = _IOC_DIR(request);
	int size = _IOC_SIZE(request);
	void* param = (void*)t->regs().edx;

	debug("handling ioctl(0x%x): type:0x%x nr:0x%x dir:0x%x size:%d",
	      request, type, nr, dir, size);

	assert_exec(t, !t->is_desched_event_syscall(),
		    "Failed to skip past desched ioctl()");

	/* Some ioctl()s are irregular and don't follow the _IOC()
	 * conventions.  Special case them here. */
	switch (request) {
	case SIOCETHTOOL: {
		struct ifreq ifr;
		t->read_mem(param, &ifr);

		record_scratch_stack_page(t);
		record_child_data(t, sizeof(struct ethtool_cmd), ifr.ifr_data);
		return;
	}
	case SIOCGIFCONF: {
		struct ifconf ifconf;
		t->read_mem(param, &ifconf);

		record_scratch_stack_page(t);
		record_parent_data(t, sizeof(ifconf), param, &ifconf);
		record_child_data(t, ifconf.ifc_len, ifconf.ifc_buf);
		return;
	}
	case SIOCGIFADDR:
	case SIOCGIFFLAGS:
	case SIOCGIFINDEX:
	case SIOCGIFMTU:
	case SIOCGIFNAME:
		record_scratch_stack_page(t);
		return record_ioctl_data(t, sizeof(struct ifreq));

	case SIOCGIWRATE:
		// SIOCGIWRATE hasn't been observed to write beyond
		// tracees' stacks, but we record a stack page here
		// just in case the behavior is driver-dependent.
		record_scratch_stack_page(t);
		return record_ioctl_data(t, sizeof(struct iwreq));

	case TCGETS:
		return record_ioctl_data(t, sizeof(struct termios));
	case TIOCINQ:
		return record_ioctl_data(t, sizeof(int));
	case TIOCGWINSZ:
		return record_ioctl_data(t, sizeof(struct winsize));
	}

	/* In ioctl language, "_IOC_WRITE" means "outparam".  Both
	 * READ and WRITE can be set for inout params. */
	if (!(_IOC_WRITE & dir)) {
		/* If the kernel isn't going to write any data back to
		 * us, we hope and pray that the result of the ioctl
		 * (observable to the tracee) is deterministic. */
		debug("  (deterministic ioctl, nothing to do)");
		return;
	}

	/* The following are thought to be "regular" ioctls, the
	 * processing of which is only known to (observably) write to
	 * the bytes in the structure passed to the kernel.  So all we
	 * need is to record |size| bytes.*/
	switch (request) {
	/* TODO: what are the 0x46 ioctls? */
	case 0xc020462b:
	case 0xc048464d:
	case 0xc0204637:
	case 0xc0304627:
		fatal("Unknown 0x46-series ioctl nr 0x%x", nr);
		break;	/* not reached */

	/* The following are ioctls for the linux Direct Rendering
	 * Manager (DRM).  The ioctl "type" is 0x64 (100, or ASCII 'd'
	 * as they docs helpfully declare it :/).  The ioctl numbers
	 * are allocated as follows
	 *
	 *  [0x00, 0x40) -- generic commands
	 *  [0x40, 0xa0) -- device-specific commands
	 *  [0xa0, 0xff) -- more generic commands
	 *
	 * Chasing down unknown ioctls is somewhat annoying in this
	 * scheme, but here's an example: request "0xc0406481".  "0xc"
	 * means it's a read/write ioctl, and "0x0040" is the size of
	 * the payload.  The actual ioctl request is "0x6481".
	 *
	 * As we saw above, "0x64" is the DRM type.  So now we need to
	 * see what command "0x81" is.  It's in the
	 * device-specific-command space, so we can start by
	 * subtracting "0x40" to get a command "0x41".  Then
	 *
	 *  $ cd 
	 *  $ grep -rn 0x41 *
	 *  nouveau_drm.h:200:#define DRM_NOUVEAU_GEM_PUSHBUF        0x41
	 *
	 * Well that was lucky!  So the command is
	 * DRM_NOUVEAU_GEM_PUSHBUF, and the parameters etc can be
	 * tracked down from that.
	 */

	/* TODO: At least one of these ioctl()s, most likely
	 * NOUVEAU_GEM_NEW, opens a file behind rr's back on behalf of
	 * the callee.  That wreaks havoc later on in execution, so we
	 * disable the whole lot for now until rr can handle that
	 * behavior (by recording access to shmem segments). */
	case DRM_IOCTL_VERSION:
	case DRM_IOCTL_NOUVEAU_GEM_NEW:
	case DRM_IOCTL_NOUVEAU_GEM_PUSHBUF:
		fatal("Intentionally unhandled DRM(0x64) ioctl nr 0x%x", nr);
		break;

	case DRM_IOCTL_GET_MAGIC:
	case DRM_IOCTL_RADEON_INFO:
	case DRM_IOCTL_I915_GEM_PWRITE:
	case DRM_IOCTL_GEM_OPEN:
	case DRM_IOCTL_I915_GEM_MMAP:
	case DRM_IOCTL_RADEON_GEM_CREATE:
	case DRM_IOCTL_RADEON_GEM_GET_TILING:
		fatal("Not-understood DRM(0x64) ioctl nr 0x%x", nr);
		break;	/* not reached */

	case 0x4010644d:
	case 0xc0186441:
	case 0x80086447:
	case 0xc0306449:
	case 0xc030644b:
		fatal("Unknown DRM(0x64) ioctl nr 0x%x", nr);
		break;	/* not reached */

	default:
		print_register_file_tid(t);
		assert_exec(t, 0,
			    "Unknown ioctl(0x%x): type:0x%x nr:0x%x dir:0x%x size:%d addr:%p",
			    request, type, nr, dir, size,
			    (void*)t->regs().edx);
	}
}

static void process_ipc(Task* t, int call)
{
	debug("ipc call: %d\n", call);

	switch (call) {
	case MSGCTL: {
		int cmd = get_ipc_command(t->regs().edx);
		void* buf = (void*)t->regs().edi;
		ssize_t buf_size;
		switch (cmd) {
		case IPC_STAT:
		case MSG_STAT:
			buf_size = sizeof(struct msqid64_ds);
			break;
		case IPC_INFO:
		case MSG_INFO:
			buf_size = sizeof(struct msginfo);
			break;
		default:
			buf_size = 0;
		}
		record_child_data(t, buf_size, buf);
		return;
	}
	case MSGRCV: {
		// The |msgsize| arg is only the size of message
		// payload; there's also a |msgtype| tag set just
		// before the payload.
		size_t buf_size = sizeof(long) + t->regs().edx;
		struct ipc_kludge_args kludge;
		void* child_kludge = (void*)t->regs().edi;

		t->read_mem(child_kludge, &kludge);
		if (has_saved_arg_ptrs(t)) {
			void* src = kludge.msgbuf;
			void* dst = pop_arg_ptr<void>(t);

			kludge.msgbuf = dst;
			t->write_mem(child_kludge, kludge);

			t->remote_memcpy((byte*)dst, (byte*)src, buf_size);
		}
		record_child_data(t, buf_size, kludge.msgbuf);
		return;
	}
	case MSGGET:
	case MSGSND:
		return;
	default:
		fatal("Unhandled IPC call %d", call);
	}
}

static void process_socketcall(Task* t, int call, void* base_addr)
{
	debug("socket call: %d\n", call);

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
		struct {
			long sockfd;
			struct sockaddr* addr;
			socklen_t* addrlen;
		} args;
		t->read_mem(base_addr, &args);
		socklen_t len = t->read_word(args.addrlen);
		record_child_data(t, sizeof(*args.addrlen), args.addrlen);
		record_child_data(t, len, args.addr);
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
		struct { long words[4]; } args;
		void* buf;
		void* argsp;
		byte* iter;
		void* data = NULL;
		ssize_t nrecvd;

		nrecvd = t->regs().eax;
		if (has_saved_arg_ptrs(t)) {
			buf = pop_arg_ptr<void>(t);
			argsp = pop_arg_ptr<void>(t);
			data = start_restoring_scratch(t, &iter);
			/* We don't need to record the fudging of the
			 * socketcall arguments, because we won't
			 * replay that. */
			memcpy(args.words, iter, sizeof(args.words));
			iter += sizeof(args);
		} else {
			long* argsp;
			read_socketcall_args(t, &argsp, &args);
			buf = (void*)args.words[1];
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
			struct user_regs_struct r = t->regs();
			/* Restore the pointer to the original args. */
			r.ecx = (uintptr_t)argsp;
			t->set_regs(r);
			finish_restoring_some_scratch(t, iter, &data);
		}
		return;
	}
	case SYS_RECVFROM: {
		struct recvfrom_args args;
		t->read_mem(base_addr, &args);

		int recvdlen = t->regs().eax;
		if (has_saved_arg_ptrs(t)) {
			byte* src_addrp = pop_arg_ptr<byte>(t);
			void* addrlenp = pop_arg_ptr<void>(t);
			byte* buf = pop_arg_ptr<byte>(t);
			byte* argsp = pop_arg_ptr<byte>(t);

			if (recvdlen > 0) {
				t->remote_memcpy(buf, args.buf, recvdlen);
			}
			args.buf = buf;

			if (src_addrp) {
				socklen_t addrlen;
				t->read_mem(args.addrlen, &addrlen);
				t->remote_memcpy(src_addrp, args.src_addr,
						 addrlen);
				t->write_mem(addrlenp, addrlen);
				args.src_addr = (struct sockaddr*)src_addrp;
				args.addrlen = (socklen_t*)addrlenp;
			}
			struct user_regs_struct r = t->regs();
			r.ecx = (uintptr_t)argsp;
			t->set_regs(r);
		}

		if (recvdlen > 0) {
			record_child_data(t, recvdlen, args.buf);
		} else {
			record_noop_data(t);
		}
		if (args.src_addr) {
			socklen_t addrlen;
			t->read_mem(args.addrlen, &addrlen);

			record_child_data(t, sizeof(*args.addrlen),
					  args.addrlen);
			record_child_data(t, addrlen, args.src_addr);
		} else {
			record_noop_data(t);
			record_noop_data(t);
		}
		return;
	}
	/* ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags); */
	case SYS_RECVMSG: {
		struct user_regs_struct r = t->regs();
		struct recvmsg_args* tmpargsp = (struct recvmsg_args*)r.ecx;
		struct recvmsg_args tmpargs;
		t->read_mem(tmpargsp, &tmpargs);
		if (!has_saved_arg_ptrs(t)) {
			return record_struct_msghdr(t, tmpargs.msg);
		}

		byte* argsp = pop_arg_ptr<byte>(t);
		struct recvmsg_args args;
		t->read_mem(argsp, &args);

		struct msghdr msg, tmpmsg;
		t->read_mem(args.msg, &msg);
		t->read_mem(tmpargs.msg, &tmpmsg);

		msg.msg_namelen = tmpmsg.msg_namelen;
		msg.msg_flags = tmpmsg.msg_flags;
		t->write_mem(args.msg, msg);
		record_parent_data(t, sizeof(tmpmsg), args.msg, &msg);

		if (msg.msg_name) {
			t->remote_memcpy(msg.msg_name, tmpmsg.msg_name,
					 tmpmsg.msg_namelen);
		}
		record_child_data(t, msg.msg_namelen, msg.msg_name);

		assert_exec(t, msg.msg_iovlen == tmpmsg.msg_iovlen,
			    "Scratch msg should have %d iovs, but has %d",
			    msg.msg_iovlen, tmpmsg.msg_iovlen);
		struct iovec iovs[msg.msg_iovlen];
		read_iovs(t, msg, iovs);
		struct iovec tmpiovs[tmpmsg.msg_iovlen];
		read_iovs(t, tmpmsg, tmpiovs);
		for (size_t i = 0; i < msg.msg_iovlen; ++i) {
			struct iovec* iov = &iovs[i];
			const struct iovec& tmpiov = tmpiovs[i];
			t->remote_memcpy(iov->iov_base, tmpiov.iov_base,
					 tmpiov.iov_len);
			iov->iov_len = tmpiov.iov_len;

			record_child_data(t, iov->iov_len, iov->iov_base);
		}

		if (msg.msg_control) {
			t->remote_memcpy(msg.msg_control, tmpmsg.msg_control,
					 tmpmsg.msg_controllen);
		}
		record_child_data(t, msg.msg_controllen, msg.msg_control);

		r.ecx = (uintptr_t)argsp;
		t->set_regs(r);
		return;
	}

	/*
	 *  int getsockopt(int sockfd, int level, int optname, const void *optval, socklen_t* optlen);
	 */
	case SYS_GETSOCKOPT: {
		struct { long sockfd; long level; int optname;
			void* optval; socklen_t* optlen; } args;
		t->read_mem(base_addr, &args);
		socklen_t optlen = t->read_word(args.optlen);
		record_child_data(t, sizeof(*args.optlen), args.optlen);
		record_child_data(t, optlen, args.optval);
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
		struct user_regs_struct r = t->regs();
		struct sockaddr* addrp = pop_arg_ptr<struct sockaddr>(t);
		socklen_t* addrlenp = pop_arg_ptr<socklen_t>(t);
		byte* orig_argsp = pop_arg_ptr<byte>(t);

		byte* iter;
		void* data = start_restoring_scratch(t, &iter);
		// Consume the scratch args.
		if (SYS_ACCEPT == call) {
			iter += sizeof(struct accept_args);
		} else {
			iter += sizeof(struct accept4_args);
		}
		socklen_t addrlen = *(socklen_t*)iter;
		restore_and_record_arg_buf(t, sizeof(addrlen), (byte*)addrlenp,
					   &iter);
		restore_and_record_arg_buf(t, addrlen, (byte*)addrp, &iter);

		/* Restore the pointer to the original args. */
		r.ecx = (uintptr_t)orig_argsp;
		t->set_regs(r);

		finish_restoring_some_scratch(t, iter, &data);
		return;
	}

	/* int socketpair(int domain, int type, int protocol, int sv[2]);
	 *
	 * values returned in sv
	 */
	case SYS_SOCKETPAIR: {
		struct { int domain; int type; int protocol; int* sv; } args;
		t->read_mem(base_addr, &args);
		record_child_data(t, 2 * sizeof(*args.sv), args.sv);
		return;
	}

	default:
		fatal("Unknown socketcall %d", call);
	}
}

void rec_process_syscall(Task *t)
{
	/* TODO: extend syscall_defs.h in order to generate code
	 * automatically for the "regular" syscalls.
	 *
	 * Macros to make the recording of syscalls easier. The suffix
	 * denotes the number of buffers that have to be recorded,
	 * which can usually be inferred from the syscall function
	 * signature. */
#define SYS_REC0(_syscall)     \
	case SYS_##_syscall:   \
		break

#define SYS_REC1(_syscall, _size, _reg)					\
	case SYS_##_syscall:						\
		record_child_data(t, _size, (void*)t->regs()._reg);	\
		break

#define SYS_REC1_STR(_syscall, _reg)			     \
	case SYS_##_syscall:				     \
		record_child_str(t, (void*)t->regs()._reg);  \
		break

#define SYS_REC2(_syscall, _size1, _reg1, _size2, _reg2)	      \
	case SYS_##_syscall:					      \
		record_child_data(t, _size1, (void*)t->regs()._reg1); \
		record_child_data(t, _size2, (void*)t->regs()._reg2); \
		break

#define SYS_REC3(_syscall, _size1, _reg1, _size2, _reg2, _size3, _reg3) \
	case SYS_##_syscall:						\
		record_child_data(t, _size1, (void*)t->regs()._reg1);	\
		record_child_data(t, _size2, (void*)t->regs()._reg2);	\
		record_child_data(t, _size3, (void*)t->regs()._reg3);	\
		break

#define SYS_REC4(_syscall, _size1, _reg1, _size2, _reg2, _size3, _reg3, _size4, _reg4)	\
	case SYS_##_syscall:						\
		record_child_data(t, _size1, (void*)t->regs()._reg1);	\
		record_child_data(t, _size2, (void*)t->regs()._reg2);	\
		record_child_data(t, _size3, (void*)t->regs()._reg3);	\
		record_child_data(t, _size4, (void*)t->regs()._reg4);	\
		break

	pid_t tid = t->tid;
	int syscall = t->ev().syscall.no; /* FIXME: don't shadow syscall() */

	debug("%d: processing syscall: %s(%d) -- time: %u",
	      tid, syscallname(syscall), syscall, get_global_time());

	t->maybe_update_vm(syscall, STATE_SYSCALL_EXIT);

	if (const struct syscallbuf_record* rec = t->desched_rec()) {
		assert(t->ev().syscall.tmp_data_ptr != t->scratch_ptr);

		record_parent_data(t,
				   t->ev().syscall.tmp_data_num_bytes,
				   t->ev().syscall.tmp_data_ptr,
				   (byte*)rec->extra_data);
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
	SYS_REC0(access);

	/**
	 * unsigned int alarm(unsigned int seconds)
	 *
	 * The alarm() system call schedules an alarm. The process will get a SIGALRM
	 * after the requested amount of seconds.
	 *
	 */
	SYS_REC0(alarm);

	/**
	 * int brk(void *addr)
	 * brk() sets the end of the data segment to the value specified by addr, when that value is
	 * reasonable, the system has enough memory, and the process does not exceed its maximum data size
	 * (see setrlimit(2)).
	 */
	SYS_REC0(brk);

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
	case SYS_clone:	{
		pid_t new_tid = t->regs().eax;
		Task* new_task = Task::find(new_tid);
		unsigned long flags = (uintptr_t)pop_arg_ptr<void>(t);

		if (flags & CLONE_UNTRACED) {
			struct user_regs_struct r = t->regs();
			r.ebx = flags;
			t->set_regs(r);
		}

		if (t->regs().eax < 0)
			break;

		push_syscall(new_task, syscall);

		/* record child id here */
		record_child_data(new_task, sizeof(pid_t),
				  (void*)t->regs().edx);
		record_child_data(new_task, sizeof(pid_t),
				  (void*)t->regs().esi);

		record_child_data(new_task, sizeof(struct user_desc),
				  (void*)new_task->regs().edi);
		record_child_data(new_task, sizeof(pid_t),
				  (void*)new_task->regs().edx);
		record_child_data(new_task, sizeof(pid_t),
				  (void*)new_task->regs().esi);

		pop_syscall(new_task);

		init_scratch_memory(new_task);
		// The new tracee just "finished" a clone that was
		// started by its parent.  It has no pending events,
		// so it can be context-switched out.
		new_task->switchable = 1;

		break;
	}

	/**
	 *  int creat(const char *pathname, mode_t mode);
	 *
	 * creat() is equivalent to open() with flags equal to
	 * O_CREAT|O_WRONLY|O_TRUNC.
	 */
	SYS_REC0(creat);

	/**
	 * int dup2(int oldfd, int newfd)
	 *
	 * dup2()  makes newfd be the copy of oldfd, closing newfd first if necessary, but note the
	 *  following..
	 */
	SYS_REC0(dup2);

	/**
	 * int close(int fd)
	 *
	 * close()  closes  a file descriptor, so that it no longer refers to any file
	 * and may be reused.  Any record locks (see fcntl(2)) held on the file it was
	 * associated with, and owned by the process,  are removed (regardless of the file
	 *  descriptor that was used to obtain the lock).
	 */
	SYS_REC0(close);

	/**
	 * int chdir(const char *path);
	 *
	 * chdir() changes the current working directory of the calling process to the directory
	 * specified in path.
	 */
	SYS_REC0(chdir);

	/**
	 * int chmod(const char *path, mode_t mode)
	 *
	 * The mode of the file given by path or referenced by fildes is changed
	 */
	SYS_REC0(chmod);

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
	SYS_REC1(clock_getres, sizeof(struct timespec), ecx);

	/**
	 * int clock_gettime(clockid_t clk_id, struct timespec *tp);
	 *
	 * The functions clock_gettime() and clock_settime() retrieve and set the time of the
	 * specified clock clk_id.
	 */
	SYS_REC1(clock_gettime, sizeof(struct timespec), ecx);

	/**
	 * int dup(int oldfd)
	 *
	 * dup() uses the lowest-numbered unused descriptor for the new descriptor.
	 */
	SYS_REC0(dup);

	/**
	 * int epoll_create(int size);
	 *
	 * epoll_create()  creates  an epoll "instance", requesting the kernel to allocate an event backing
	 * store dimensioned for size descriptors.  The size is not the maximum size of the backing store but
	 * just a hint to the kernel about how to dimension internal structures.
	 * When  no  longer  required,  the  file  descriptor returned  by epoll_create() should be closed by using close(2).
	 */
	SYS_REC0(epoll_create);

	/**
	 * int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
	 *
	 * This system call performs control operations on the epoll instance referred to by the file descriptor epfd.
	 * It requests that the operation op be performed for the target file descriptor, fd.
	 *
	 */
	SYS_REC0(epoll_ctl);

	/**
	 * int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
	 *
	 * The  epoll_wait() system call waits for events on the epoll instance referred to by the file descriptor epfd.
	 * The memory area pointed to by events will contain the events that will be available for the caller.  Up
	 * to maxevents are returned by epoll_wait().  The maxevents argument must be greater than zero.
	 */
	case SYS_epoll_wait: {
		byte* iter;
		void* data = start_restoring_scratch(t, &iter);
		struct epoll_event* events =
			pop_arg_ptr<struct epoll_event>(t);
		int maxevents = t->regs().edx;
		if (events) {
			restore_and_record_arg_buf(t,
						   maxevents * sizeof(*events),
						   (byte*)events, &iter);
			struct user_regs_struct r = t->regs();
			r.ecx = (uintptr_t)events;
			t->set_regs(r);
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
	SYS_REC0(eventfd2);

	/**
	 * int faccessat(int dirfd, const char *pathname, int mode, int flags)
	 *
	 * The  faccessat() system call operates in exactly the same way as access(2), except for the differences
	 * described in this manual page....
	 */
	SYS_REC0(faccessat);

	/**
	 * int posix_fadvise(int fd, off_t offset, off_t len, int advice);
	 *
	 * Programs can use posix_fadvise() to announce an intention to access
	 * file data in a specific pattern in the future, thus allowing the kernel
	 * to perform appropriate optimizations.
	 */
	SYS_REC0(fadvise64);
	SYS_REC0(fadvise64_64);

	/**
	 * int fallocate(int fd, int mode, off_t offset, off_t len);
	 *
	 * fallocate() allows the caller to directly manipulate the allocated disk space
	 * for the file referred to by fd for the byte range starting at offset and
	 * continuing for len bytes
	 */
	SYS_REC0(fallocate);

	/* int fcntl(int fd, int cmd, ... ( arg ));
	 *
	 *
	 * fcntl()  performs  one  of the operations described below on the open file descriptor fd.
	 * The operation is determined by cmd. fcntl() can take an optional third argument.
	 * Whether or not this argument is required is determined by cmd. The required  argument
	 * type is indicated in parentheses after each cmd name (in most cases, the required type is long,
	 * and we identify the argument using the name arg), or void is specified if the argument is not required.
	 */
	case SYS_fcntl64: {
		int cmd = t->regs().ecx;
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

		case F_GETLK:
			static_assert(sizeof(struct flock) < sizeof(struct flock64),
				      "struct flock64 not declared differently from struct flock");
			record_child_data(t, sizeof(struct flock),
					  (void*)t->regs().edx);
			break;

		case F_SETLK:
		case F_SETLKW:
			break;

		case F_GETLK64:
			record_child_data(t, sizeof(struct flock64),
					  (void*)t->regs().edx);
			break;

		case F_SETLK64:
		case F_SETLKW64:
			break;

		case F_GETOWN_EX:
			record_child_data(t, sizeof(struct f_owner_ex),
					  (void*)t->regs().edx);
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
	SYS_REC0(fchdir);

	/**
	 * int fchmod(int fd, mode_t mode);
	 *
	 * fchmod() changes the permissions of the file referred to by the open file descriptor fd */
	SYS_REC0(fchmod);

	/**
	 * int fdatasync(int fd)
	 *
	 * fdatasync() is similar to fsync(), but does not flush modified metadata unless that metadata is needed in order
	 * to allow a subsequent data retrieval to be correctly handled.  For example, changes to st_atime or st_mtime (respectively,
	 * time of last access and time of last modification; see stat(2)) do not require flushing because they are not necessary
	 * for a subsequent data read to be handled correctly.  On  the other hand, a change to the file size (st_size, as made by
	 * say ftruncate(2)), would require a metadata flush
	 */
	SYS_REC0(fdatasync);

	/**
	 * void flockfile(FILE * stream)
	 *
	 * The flockfile function acquires the internal locking object associated with the stream stream. This
 	 * ensures that no other thread can explicitly through flockfile/ftrylockfile or implicit through a call of a
 	 * stream function lock the stream. The thread will block until the lock is acquired. An explicit call to
 	 * funlockfile has to be used to release the lock.
 	 *
	 */
	SYS_REC0(flock);

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
	SYS_REC1(fstatfs, sizeof(struct statfs), ecx);
	SYS_REC1(fstatfs64, sizeof(struct statfs64), edx);

	/**
	 * int ftruncate(int fd, off_t length)
	 *
	 * The  truncate() and ftruncate() functions cause the regular file named by path or referenced by fd
	 * to be truncated to a size of precisely length bytes.
	 *
	 */
	SYS_REC0(ftruncate64);
	SYS_REC0(ftruncate);
	SYS_REC0(truncate);
	SYS_REC0(truncate64);

	/**
	 * int fsync(int fd)
	 *
	 * fsync()  transfers ("flushes") all modified in-core data of (i.e., modified buffer cache pages for)
	 * the file referred to by the file descriptor fd to the disk device (or other permanent storage device)
	 * where that file  resides.   The  call  blocks until  the  device  reports that the transfer has
	 * completed.  It also flushes metadata information associated with the file (see stat(2))
	 */
	SYS_REC0(fsync);

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
	case SYS_futex:	{
		record_child_data(t, sizeof(int), (void*)t->regs().ebx);
		int op = t->regs().ecx & FUTEX_CMD_MASK;

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
			record_child_data(t, sizeof(int), (void*)t->regs().edi);
			break;

		default:
			fatal("Unknown futex op %d", op);
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
	SYS_REC1_STR(getcwd, ebx);

	/**
	 * int getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
	 *
	 * The system call getdents() reads several linux_dirent structures from the directory referred
	 * to by the open  file  descriptor fd into the buffer pointed to by dirp.  The argument count
	 * specifies the size of that buffer.
	 *
	 */
	SYS_REC1(getdents64, t->regs().eax, ecx);
	SYS_REC1(getdents, t->regs().eax, ecx);

	/**
	 * gid_t getgid(void);
	 *
	 * getgid() returns the real group ID of the calling process.
	 */
	SYS_REC0(getgid32);

	/**
	 * gid_t getegid(void);
	 *
	 * getegid() returns the effective group ID of the calling process.
	 */
	SYS_REC0(getegid32);

	/**
	 * pid_t getpid(void);
	 *
	 * getpid() returns the process ID of the calling process.
	 * (This is often used by routines that generate unique temporary filenames.)
	 *
	 */
	SYS_REC0(getpid);

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
	SYS_REC1(getgroups32, t->regs().ebx * sizeof(gid_t), ecx);

	/**
	 * uid_t getuid(void);
	 *
	 *  getuid() returns the real user ID of the calling process
	 */
	SYS_REC0(getuid32);

	/**
	 * uid_t geteuid(void);
	 *
	 * geteuid() returns the effective user ID of the calling process.
	 */
	SYS_REC0(geteuid32);

	/**
	 * pid_t getpgid(pid_t pid);
	 *
	 * getpgid() returns the PGID of the process specified by pid.  If pid is zero,
	 * getpgid() the process ID of the calling process is used.int getrusage(int who, struct rusage *usage);
	 */
	SYS_REC0(getpgid);

	/**
	 * pid_t getppid(void);
	 *
	 * getppid() returns the process ID of the parent of the calling process.
	 */
	SYS_REC0(getppid);

	/**
	 * int getpriority(int which, int who);
	 *
	 * The scheduling priority of the process, process group, or
	 * user, as indicated by which and who is obtained with the
	 * getpriority() call.
	 */
	SYS_REC0(getpriority);

	/**
	 * pid_t gettid(void);
	 *
	 * gettid()  returns  the caller's thread ID (TID).
	 */
	SYS_REC0(gettid);

	/**
	 * int getrusage(int who, struct rusage *usage)
	 *
	 * getrusage() returns resource usage measures for who, which can be one of the following..
	 */
	SYS_REC1(getrusage, sizeof(struct rusage), ecx);

	/**
	 * int gettimeofday(struct timeval *tv, struct timezone *tz);
	 *
	 * The functions gettimeofday() and settimget_timeofday() can get and set the time as
	 * well as a timezone.  The tv argument is a struct timeval (as specified in <sys/time.h>):
	 *
	 */
	SYS_REC2(gettimeofday, sizeof(struct timeval), ebx,
		 sizeof(struct timezone), ecx);

	/**
	 *  ssize_t getxattr(const char *path, const char *name,
	 *                   void *value, size_t size);
	 *  ssize_t lgetxattr(const char *path, const char *name,
	 *                    void *value, size_t size);
	 *  ssize_t fgetxattr(int fd, const char *name,
	 *                    void *value, size_t size);
	 *
	 * getxattr() retrieves the value of the extended attribute
	 * identified by name and associated with the given path in
	 * the file system. The length of the attribute value is
	 * returned.
	 */
	case SYS_getxattr:
	case SYS_lgetxattr:
	case SYS_fgetxattr: {
		ssize_t len = t->regs().eax;
		void* value = (void*)t->regs().edx;

		if (len > 0) {
			record_child_data(t, len, value);
		} else {
			record_noop_data(t);
		}
		break;
	}

	/**
	 * int inotify_rm_watch(int fd, uint32_t wd)
	 *
	 * inotify_rm_watch()  removes the watch associated with the watch descriptor wd from the
	 * inotify instance associated with the file descriptor fd.
	 */
	SYS_REC0(inotify_rm_watch);

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
		process_ioctl(t, t->regs().ecx);
		break;

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
		process_ipc(t, t->regs().ebx);
		break;

	/**
	 * int link(const char *oldpath, const char *newpath);
	 *
	 * link() creates a new link (also known as a hard link) to an
	 * existing file.
	 */
	SYS_REC0(link);

	/**
	 * off_t lseek(int fd, off_t offset, int whence)
	 * The  lseek()  function  repositions the offset of the open file associated with the file
	 descriptor fd to the argument offset according to the directive whence as follows:
	 */
	SYS_REC0(lseek);

	/**
	 * int lstat(const char *path, struct stat *buf);
	 *
	 * lstat() is identical to stat(), except that if path is a symbolic link, then
	 * the link itself is stat-ed, not the file that it refers to.
	 */
	SYS_REC1(lstat64, sizeof(struct stat64), ecx);

	/**
	 * void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
	 *
	 * mmap()  creates  a  new  mapping in the virtual address space of the calling process.
	 * The starting address for the new mapping is specified in addr.  The length argument specifies
	 * the length of the mapping.
	 */
	SYS_REC0(munmap);

	/**
	 * pid_t getpgrp(void)
	 *
	 * The POSIX.1 getpgrp() always returns the PGID of the caller
	 */
	SYS_REC0(getpgrp);

	/**
	 * int inotify_init(void)
	 *
	 * inotify_init()  initializes  a  new inotify instance and returns a file
	 * descriptor associated with a new inotify event queue.
	 */
	SYS_REC0(inotify_init);
	SYS_REC0(inotify_init1);

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
	SYS_REC0(inotify_add_watch);

	/* int kill(pid_t pid, int sig)
	 *
	 * The kill() system call can be used to send any signal to any process group or process.
	 */
	SYS_REC0(kill);

	/**
	 * long set_robust_list(struct robust_list_head *head, size_t len)
	 *
	 * The robust futex implementation needs to maintain per-thread lists of robust futexes
	 * which are unlocked when the thread exits. These lists are managed in user space, the
	 * kernel is only notified about the location of the head of the list.

	 * set_robust_list sets the head of the list of robust futexes owned by the current thread to head.
	 * len is the size of *head.
	 */
	SYS_REC0(set_robust_list);

	/* int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid);
	 *
	 * getresuid()  returns  the  real  UID,  the effective UID, and the saved set-user-ID of
	 * the calling process, in the arguments ruid, euid, and suid, respectively.  getresgid()
	 * performs the analogous task  for  the  process's  group IDs.
	 * @return:  On success, zero is returned.  On error, -1 is returned, and errno is set appropriately.
	 */
	SYS_REC3(getresgid32, sizeof(uid_t), ebx, sizeof(uid_t), ecx,
		 sizeof(uid_t), edx);

	/**
	 * int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid)
	 *
	 * getresuid() returns the real UID, the effective UID, and the saved set-
	 * user-ID of the calling process, in the arguments ruid, euid, and  suid,
	 * respectively.    getresgid()   performs  the  analogous  task  for  the
	 * process's group IDs.
	 */
	SYS_REC3(getresuid32, sizeof(uid_t), ebx, sizeof(uid_t), ecx,
		 sizeof(uid_t), edx);

	/*
	 * int _llseek(unsigned int fd, unsigned long offset_high, unsigned long offset_low,
	 * loff_t *result, unsigned int whence);
	 *
	 * The  _llseek()  function  repositions  the offset of the open file associated with the file descriptor fd to (off‐
	 * set_high<<32) | offset_low bytes relative to the beginning of the file, the current position in the file,  or  the
	 * end  of  the  file,  depending on whether whence is SEEK_SET, SEEK_CUR, or SEEK_END, respectively.  It returns the
	 * resulting file position in the argument result.
	 */

	SYS_REC1(_llseek, sizeof(loff_t), esi);

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
	SYS_REC0(madvise);

	/**
	 * int mkdir(const char *pathname, mode_t mode);
	 *
	 * mkdir() attempts to create a directory named pathname.
	 */
	SYS_REC0(mkdir);

	/**
	 * int mkdirat(int dirfd, const char *pathname, mode_t mode);
	 *
	 * The mkdirat() system call operates in exactly the same way as mkdir(2), except
	 * for the differences described in this manual page....
	 *
	 */
	SYS_REC0(mkdirat);

	/**
	 * int mprotect(const void *addr, size_t len, int prot)
	 *
	 * mprotect()  changes  protection for the calling process's memory page(s) containing any
	 * part of the address range in the interval [addr, addr+len-1].  addr must be aligned to a
	 *  page boundary.

	 * If the calling process tries to access memory in a manner that violates the  protection,  then  the
	 * kernel generates a SIGSEGV signal for the process
	 */
	SYS_REC0(mprotect);

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

	SYS_REC4(_newselect, sizeof(fd_set), ecx, sizeof(fd_set), edx,
		 sizeof(fd_set), esi, sizeof(struct timeval), edi);

	/**
	 * int open(const char *pathname, int flags)
	 * int open(const char *pathname, int flags, mode_t mode)
	 */
	case SYS_open: {
		string pathname = t->read_c_str((void*)t->regs().ebx);
		if (is_blacklisted_filename(pathname.c_str())) {
			/* NB: the file will still be open in the
			 * process's file table, but let's hope this
			 * gross hack dies before we have to worry
			 * about that. */
			log_warn("Cowardly refusing to open %s",
				 pathname.c_str());
			struct user_regs_struct r = t->regs();
			r.eax = -ENOENT;
			t->set_regs(r);
		}
		break;
	}

	/**
	 * int openat(int dirfd, const char *pathname, int flags);
	 * int openat(int dirfd, const char *pathname, int flags, mode_t mode);
	 *
	 * The  openat() system call operates in exactly the same way as open(2), except for the
	 * differences described in this manual page.
	 */
	SYS_REC0(openat);

	/**
	 *  int perf_event_open(struct perf_event_attr *attr,
	 *                      pid_t pid, int cpu, int group_fd,
         *                      unsigned long flags);
	 *
	 * Given a list of parameters, perf_event_open() returns a
	 * file descriptor, for use in subsequent system calls
	 * (read(2), mmap(2), prctl(2), fcntl(2), etc.).
	 */
	SYS_REC0(perf_event_open);

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
	SYS_REC1(pipe, sizeof(int[2]), ebx);

	/**
	 * int pipe2(int pipefd[2], int flags)
	 *
	 * If flags is 0, then pipe2() is the same as pipe().  The following values can be bitwise
	 * ORed in flags to obtain different behavior...
	 */
	SYS_REC1(pipe2, sizeof(int[2]), ebx);

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
		byte* iter;
		void* data = start_restoring_scratch(t, &iter);
		struct pollfd* fds = pop_arg_ptr<struct pollfd>(t);
		size_t nfds = t->regs().ecx;

		restore_and_record_arg_buf(t, nfds * sizeof(*fds), (byte*)fds,
					   &iter);
		struct user_regs_struct r = t->regs();
		r.ebx = (uintptr_t)fds;
		t->set_regs(r);
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
		switch (t->regs().ebx) {
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

		case PR_SET_NAME:
			t->update_prname((void*)t->regs().ecx);
			// fall through
		case PR_GET_NAME:
			// We actually execute these during replay, so
			// no need to save any data.
			size = 0;
			break;

		default:
			size = 0;
			break;
		}
		if (size > 0) {
			byte* iter;
			void* data = start_restoring_scratch(t, &iter);
			byte* arg = pop_arg_ptr<byte>(t);

			restore_and_record_arg_buf(t, size, arg, &iter);
			struct user_regs_struct r = t->regs();
			r.ecx = (uintptr_t)arg;
			t->set_regs(r);

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
	SYS_REC1(pread64, t->regs().eax, ecx);
	SYS_REC0(pwrite64);

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
	SYS_REC1(prlimit64, sizeof(struct rlimit64), esi);

	/**
	 * int quotactl(int cmd, const char *special, int id, caddr_t addr);
	 *
	 * The  quotactl()  call  manipulates disk quotas.  The cmd argument indi‐
	 * cates a command to be applied to the user or group ID specified in  id.
	 * To  initialize the cmd argument, use the QCMD(subcmd, type) macro.  The
	 * type value is either USRQUOTA, for user quotas, or GRPQUOTA, for  group
	 * quotas.  The subcmd value is described below.
	 */
	case SYS_quotactl: {
		 int cmd = t->regs().ebx;
		 void* addr = (void*)t->regs().esi;
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
	SYS_REC0(readahead);

	/**
	 * ssize_t readlink(const char *path, char *buf, size_t bufsiz);
	 *
	 * readlink() places the contents of the symbolic link path in the buffer
	 * buf, which has size bufsiz. readlink() does not append a null byte to buf.
	 * It will truncate the contents (to a length of bufsiz characters), in case
	 * the buffer is too small to hold all of the contents.
	 */
	SYS_REC1(readlink, t->regs().edx, ecx);

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
		void* old_sigaction = (void*)t->regs().edx;
		record_child_data(t, sizeof(struct kernel_sigaction),
				  old_sigaction);
		t->update_sigaction();
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
	case SYS_sigprocmask:
	case SYS_rt_sigprocmask: {
		void* oldsetp = (void*)t->regs().edx;
		record_child_data(t, sizeof(sigset_t), oldsetp);
		t->update_sigmask();
		break;
	}

	/**
	 * int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask);
	 *
	 * sched_getaffinity()  writes  the affinity mask of the process whose ID is pid into the cpu_set_t structure
	 * pointed to by mask.  The cpusetsize argument specifies the
	 *  size (in bytes) of mask.  If pid is zero, then the mask of the calling process is returned.
	 */
	SYS_REC1(sched_getaffinity, sizeof(cpu_set_t), edx);

	/**
	 * int sched_getparam(pid_t pid, struct sched_param *param)
	 *
	 * sched_getparam()  retrieves  the  scheduling  parameters  for  the  process  i
	 * dentified  by  pid.  If pid is zero, then the parameters of the calling process
	 * are retrieved.
	 */
	SYS_REC1(sched_getparam, sizeof(struct sched_param), ecx);

	/**
	 *  int sched_get_priority_max(int policy)
	 *
	 * sched_get_priority_max() returns the maximum priority value that can be
	 * used    with   the   scheduling   algorithm   identified   by   policy.
	 */
	SYS_REC0(sched_get_priority_max);

	/**
	 * int sched_get_priority_min(int policy)
	 *
	 * sched_get_priority_min() returns the minimint fdatasync(int fd);um priority value that can be used
	 * with the scheduling algorithm identified by  policy.
	 */
	SYS_REC0(sched_get_priority_min);

	/**
	 * int sched_getscheduler(pid_t pid);
	 *
	 * sched_getscheduler() queries the scheduling policy currently applied to the
	 * process identified by pid.  If pid equals zero, the policy  of  the  calling
	 * process will be retrieved.
	 */
	SYS_REC0(sched_getscheduler);

	/**
	 * int sched_setscheduler(pid_t pid, int policy, const struct sched_param *param);
	 *
	 * sched_setscheduler()  sets  both the scheduling policy and the associated parameters
	 * for the process whose ID is specified in pid.  If pid equals zero, the scheduling policy
	 * and parameters of the calling process will be set.  The interpretation of the argument
	 * param depends on the selected policy.
	 */
	SYS_REC0(sched_setscheduler);

	/**
	 * int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask);
	 *
	 * sched_setaffinity()  sets the CPU affinity mask of the process whose ID
	 * is pid to the value specified by mask.  If pid is zero, then the  call‐
	 * ing  process is used.  The argument cpusetsize is the length (in bytes)
	 * of the data pointed to by mask.  Normally this argument would be speci‐
	 * fied as sizeof(cpu_set_t).
	 */
	case SYS_sched_setaffinity: {
		if (SYSCALL_FAILED(t->regs().eax)) {
			// Nothing to do
			break;
		}

		Task *target = t->regs().ebx ? Task::find(t->regs().ebx) : t;
		if (target) {
			ssize_t cpuset_len = t->regs().ecx;
			void* child_cpuset = (void*)t->regs().edx;
			// The only sched_setaffinity call we allow on
			// an rr-managed task is one that sets
			// affinity to CPU 0.
			assert_exec(t, cpuset_len == sizeof(cpu_set_t),
				    "Invalid sched_setaffinity parameters");
			cpu_set_t cpus;
			target->read_mem(child_cpuset, &cpus);
			assert_exec(t, (CPU_COUNT(&cpus) == 1
					&&  CPU_ISSET(0, &cpus)),
			            "Invalid affinity setting");
		}
		break;
	}

	/**
	 * int sched_yield(void)
	 *
	 * sched_yield() causes the calling thread to relinquish the CPU.  The thread is moved to the end of
	 * the queue for its static priority and a new thread gets to run.
	 */
	SYS_REC0(sched_yield);

	/**
	 * int setitimer(int which, const struct itimerval *new_value, struct itimerval *old_value);
	 *
	 */
	SYS_REC1(setitimer, sizeof(struct itimerval), edx);

	/**
	 * int setpriority(int which, int who, int prio);
	 *
	 * The scheduling priority of the process, process group, or
	 * user, as indicated by which and who is set with the
	 * setpriority() call.
	 */
	case SYS_setpriority: {
		// The syscall might have failed due to insufficient
		// permissions (e.g. while trying to decrease the nice value
		// while not root).
		// We'll choose to honor the new value anyway since we'd like
		// to be able to test configurations where a child thread
		// has a lower nice value than its parent, which requires
		// lowering the child's nice value.
		if (t->regs().ebx == PRIO_PROCESS) {
			Task *target = t->regs().ecx ? Task::find(t->regs().ecx) : t;
			if (target) {
				debug("Setting nice value for tid %d to %ld", tid, t->regs().edx);
				target->set_priority(t->regs().edx);
			}
		}
		break;
	}

	/**
	 * int setregid(gid_t rgid, gid_t egid)
	 *
	 * setreuid() sets real and effective user IDs of the calling process
	 */
	SYS_REC0(setregid32);

	/**
	 * int setresgid(gid_t rgid, gid_t egid, gid_t sgid);
	 *
	 * setresgid() sets the real GID, effective GID, and saved set-group-ID of the calling process.
	 *
	 */
	SYS_REC0(setresgid32);

	/**
	 * int setresuid(uid_t ruid, uid_t euid, uid_t suid);
	 *
	 * setresuid() sets the real user ID, the effective user ID, and the saved set-user-ID of the calling process.
	 *
	 */
	SYS_REC0(setresuid32);

	/**
	 * pid_t setsid(void);
	 *
	 * setsid() creates a new session if the calling process is not a process group leader.
	 */
	SYS_REC0(setsid);

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
	SYS_REC1(set_thread_area, sizeof(struct user_desc), ebx);

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
	case SYS_set_tid_address: {
		void* addr = (void*)t->regs().ebx;
		record_child_data(t, sizeof(pid_t), addr);
		t->set_tid_addr(addr);
	}

	/**
	 * int sigaltstack(const stack_t *ss, stack_t *oss)
	 *
	 * sigaltstack()  allows a process to define a new alternate signal stack and/or retrieve the state of
	 * an existing alternate signal stack.  An alternate signal stack is used during the execution of a signal
	 * handler if the establishment of that handler (see sigaction(2)) requested it.
	 */
	SYS_REC1(sigaltstack, t->regs().ecx ? sizeof(stack_t) : 0, ecx);

	/**
	 * int sigreturn(unsigned long __unused)
	 *
	 * When  the Linux kernel creates the stack frame for a signal handler, a call to sigreturn()
	 * is inserted into the stack frame so that upon return from the signal handler, sigreturn() will
	 * be called.
	 */
	SYS_REC0(sigreturn);

	/**
	 * int socketcall(int call, unsigned long *args)
	 *
	 * socketcall()  is  a common kernel entry point for the socket system calls.  call determines
	 * which socket function to invoke.  args points to a block containing the actual arguments,
	 * which  are  passed  through  to  the appropriate call.
	 *
	 */
	case SYS_socketcall:
		process_socketcall(t, t->regs().ebx, (void*)t->regs().ecx);
		break;

	/**
	 *  int stat(const char *path, struct stat *buf);
	 *
	 *  stat() stats the file pointed to by path and fills in buf.
	 */
	SYS_REC1(stat64, sizeof(struct stat64), ecx);

	/**
	 * int statfs(const char *path, struct statfs *buf)
	 *
	 * The function statfs() returns information about a mounted file system.  path is the pathname of any file within the mounted
	 * file system.  buf is a pointer to a statfs structure defined approximately as follows:
	 */
	SYS_REC1(statfs, sizeof(struct statfs), ecx);

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
	SYS_REC1(statfs64, sizeof(struct statfs64), edx);

	/**
	 * int symlink(const char *oldpath, const char *newpath)
	 *
	 * symlink() creates a symbolic link named newpath which contains the string oldpath.
	 */
	SYS_REC0(symlink);

	/**
	 * int sysinfo(struct sysinfo *info)
	 *
	 * sysinfo() provides a simple way of getting overall system statistics.
	 */
	SYS_REC1(sysinfo, sizeof(struct sysinfo), ebx);

	/**
	 * int tgkill(int tgid, int tid, int sig)
	 * tgkill()  sends  the  signal sig to the thread with the thread ID tid in the thread group tgid.  (By contrast, kill(2) can only be used to send a
	 * signal to a process (i.e., thread group) as a whole, and the signal will be delivered to an arbitrary thread within that process.)
	 */
	SYS_REC0(tgkill);

	/**
	 * time_t time(time_t *t);
	 *
	 * time() returns the time since the Epoch (00:00:00 UTC, January 1, 1970), measured
	 *  in seconds. If t is non-NULL, the return value is also stored in the memory pointed
	 *  to by t.
	 */
	SYS_REC1(time, sizeof(time_t), ebx);

	/**
	 * clock_t times(struct tms *buf)
	 *
	 * times()  stores  the  current  process  times in the struct tms that buf points to.  The
	 *  struct tms is as defined in <sys/times.h>:
	 */
	SYS_REC1(times, sizeof(struct tms), ebx);

	/**
	 * int getrlimit(int resource, struct rlimit *rlim)
	 *
	 * getrlimit()  and  setrlimit()  get and set resource limits respectively.
	 * Each resource has an associated soft and hard limit, as defined by the rlimit structure
	 * (the rlim argument to both getrlimit() and setrlimit()):
	 */
	SYS_REC1(ugetrlimit, sizeof(struct rlimit), ecx);

	/**
	 * int uname(struct utsname *buf)
	 *
	 * uname() returns system information in the structure pointed to by buf. The utsname
	 * struct is defined in <sys/utsname.h>:
	 */
	SYS_REC1(uname, sizeof(struct utsname), ebx);

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
	SYS_REC0(utime);

	/**
	 * int utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags);
	 *
	 * utimensat() and futimens() update the timestamps of a file with nanosecond precision.  This
	 * contrasts with the historical utime(2) and utimes(2), which permit only second and microsecond precision,
	 * respectively, when setting file timestamps.
	 */
	SYS_REC0(utimensat);

	/* signature:
	 * int execve(const char *filename, char *const argv[], char *const envp[]);
	 */
	case SYS_execve:
		process_execve(t);
		break;

	/**
	 * int fstat(int fd, struct stat *buf)
	 *
	 * fstat()  is  identical  to  stat(),  except  that  the  file to be stat-ed is specified
	 * by the file descriptor fd.
	 *
	 */

	SYS_REC1(fstat64, sizeof(struct stat64), ecx);

	/**
	 * int fstatat(int dirfd, const char *pathname, struct stat *buf, int flags);
	 *
	 * The  fstatat()  system  call operates in exactly the same way as stat(2), except for the
	 * differences described in this manual page....
	 */
	SYS_REC1(fstatat64, sizeof(struct stat64), edx);

	/**
	 * pid_t fork(void)
	 *
	 * fork()  creates  a new process by duplicating the calling process.  The new process, referred to as
	 * the child, is an exact duplicate of the calling process, referred to as the parent, except for the
	 * following points...
	 *
	 */
	SYS_REC0(fork);

	/**
	 *  void *mmap2(void *addr, size_t length, int prot,int flags, int fd, off_t pgoffset);
	 *
	 * The mmap2() system call operates in exactly the same way as
	 * mmap(2), except that the final argument specifies the
	 * offset into the file in 4096-byte units (instead of bytes,
	 * as is done by mmap(2)).  This enables applications that use
	 * a 32-bit off_t to map large files (up to 2^44 bytes).
	 */
	case SYS_mmap2: {
		if (SYSCALL_FAILED(t->regs().eax)) {
			// We purely emulate failed mmaps.
			break;
		}

		void* addr = (void*)t->regs().eax;
		size_t size = ceil_page_size(t->regs().ecx);
		int prot = t->regs().edx, flags = t->regs().esi,
		      fd = t->regs().edi;
		off_t offset_pages = t->regs().ebp;
		if (flags & MAP_ANONYMOUS) {
			// Anonymous mappings are by definition not
			// backed by any file-like object, and are
			// initialized to zero, so there's no
			// nondeterminism to record.
			//assert(!(flags & MAP_UNINITIALIZED));
			t->vm()->map(addr, size, prot, flags, 0,
				     MappableResource::anonymous());
			break;
		}

		assert_exec(t, fd >= 0, "Valid fd required for file mapping");
		assert(!(flags & MAP_GROWSDOWN));

		struct mmapped_file file;
		// TODO: save a reflink copy of the resource to the
		// trace directory as |fs/[st_dev].[st_inode]|.  Then
		// we wouldn't have to care about looking up a name
		// for the resource.
		file.time = get_global_time();
		file.tid = tid;
		if (!t->fdstat(fd, &file.stat,
			       file.filename, sizeof(file.filename))) {
			fatal("Failed to fdstat %d", fd);
		}
		file.start = addr;
		file.end = (byte*)addr + size;

		if (strstr(file.filename, SYSCALLBUF_LIB_FILENAME)
		    && (prot & PROT_EXEC) ) {
			t->syscallbuf_lib_start = file.start;
			t->syscallbuf_lib_end = file.end;
		}

		file.copied = should_copy_mmap_region(file.filename,
						      &file.stat,
						      prot, flags,
						      WARN_DEFAULT);
		if (file.copied) {
			record_child_data(t, size, addr);
		}
		record_mmapped_file_stats(&file);

		t->vm()->map(addr, size, prot, flags,
			     page_size() * offset_pages,
			     MappableResource(FileId(file.stat),
					      file.filename));
		break;
	}

	/*
	 * void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, ... ( void *new_address ));
	 *
	 *  mremap()  expands  (or  shrinks) an existing memory mapping, potentially moving it at the same time
	 *  (controlled by the flags argument and the available virtual address space).
	 */
	SYS_REC0(mremap);

	SYS_REC0(msync);

	/**
	 * int nanosleep(const struct timespec *req, struct timespec *rem)
	 *
	 * nanosleep()  suspends  the  execution  of the calling thread until either at least the time specified in *req has
	 * elapsed, or the delivery of a signal that triggers the invocation of a handler in the calling thread or that ter-
	 * minates the process.
	 */
	case SYS_nanosleep: {
		struct timespec* rem = pop_arg_ptr<struct timespec>(t);
		byte* iter;
		void* data = start_restoring_scratch(t, &iter);

		if (rem) {
			struct user_regs_struct r = t->regs();
			/* If the sleep completes, the kernel doesn't
			 * write back to the remaining-time
			 * argument. */
			if (0 == r.eax) {
				record_noop_data(t);
			} else {
				/* TODO: where are we supposed to
				 * write back these args?  We don't
				 * see an EINTR return from
				 * nanosleep() when it's interrupted
				 * by a user-handled signal. */
				restore_and_record_arg(t, rem, &iter);
			}
			r.ecx = (uintptr_t)rem;
			t->set_regs(r);
		}

		finish_restoring_some_scratch(t, iter, &data);
		break;
	}

	SYS_REC0(pause);

	/**
	 * int rmdir(const char *pathname)
	 *
	 * rmdir() deletes a directory, which must be empty.
	 */
	SYS_REC0(rmdir);

	/**
	 * ssize_t write(int fd, const void *buf, size_t count)
	 *
	 * write() writes up to count bytes to the file referenced by the file descriptor fd
	 * write()  from the buffer starting at buf. POSIX requires that a read() which can be
	 * proved to occur after a write() has returned returns the new data. Note that not all file
	 *  systems are POSIX conforming.
	 */
	SYS_REC0(write);

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
		byte* iter;
		void* data = nullptr;

		nread = t->regs().eax;
		if (has_saved_arg_ptrs(t)) {
			buf = pop_arg_ptr<void>(t);
			data = start_restoring_scratch(t, &iter);
		} else {
			buf = (void*)t->regs().ecx;
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
			struct user_regs_struct r = t->regs();
			r.ecx = (uintptr_t)buf;
			t->set_regs(r);
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
		struct mmsghdr* msg = (struct mmsghdr*)t->regs().ecx;
		ssize_t nmmsgs = t->regs().eax;
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
	SYS_REC0(rename);

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
		struct mmsghdr* msg = (struct mmsghdr*)t->regs().ecx;
		ssize_t nmmsgs = t->regs().eax;
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
	SYS_REC0(setpgid);

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
	SYS_REC1(setrlimit, sizeof(struct rlimit), ecx);

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
	case SYS_splice: {
		loff_t* off_out = pop_arg_ptr<loff_t>(t);
		loff_t* off_in = pop_arg_ptr<loff_t>(t);
		byte* iter;
		void* data = start_restoring_scratch(t, &iter);

		struct user_regs_struct r = t->regs();
		if (off_in) {
			restore_and_record_arg(t, off_in, &iter);
			r.ecx = (uintptr_t)off_in;
		} else {
			record_noop_data(t);
		}
		if (off_out) {
			restore_and_record_arg(t, off_out, &iter);
			r.esi = (uintptr_t)off_out;
		} else {
			record_noop_data(t);
		}

		t->set_regs(r);
		finish_restoring_scratch(t, iter, &data);
		break;
	}

	/**
	 * mode_t umask(mode_t mask);
	 * umask()  sets  the  calling  process's file mode creation mask (umask) to mask & 0777
	 * (i.e., only the file permission bits of mask are used), and returns the previous value of the mask.
	 *
	 */
	SYS_REC0(umask);

	/**
	 * int unlink(const char *path);
	 *
	 * The unlink() function shall remove a link to a file. If path names a symbolic link, unlink()
	 * shall remove the symbolic link named by path and shall not affect any file or directory named
	 * by the contents of the symbolic link. Otherwise, unlink() shall remove the link named by the
	 * pathname pointed to by path and shall decrement the link count of the file referenced by the link.
	 *
	 */
	SYS_REC0(unlink);

	/**
	 * int unlinkat(int dirfd, const char *pathname, int flags)
	 *
	 * The unlinkat() system call operates in exactly the same way as either unlink(2) or
	 * rmdir(2) (depending on whether or not flags includes the AT_REMOVEDIR flag) except for the
	 * differences described in this manual page.
	 */
	SYS_REC0(unlinkat);

	/**
	 * int utimes(const char *filename, const struct timeval times[2])
	 *
	 * The utime() system call changes the access and modification times of the inode specified by
	 * filename to the actime and modtime fields of times respectively.
	 *
	 */
	SYS_REC1(utimes, 2 * sizeof(struct timeval), ecx);

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
		struct rusage* rusage = pop_arg_ptr<struct rusage>(t);
		int* status = pop_arg_ptr<int>(t);
		byte* iter;
		void* data = start_restoring_scratch(t, &iter);

		struct user_regs_struct r = t->regs();
		if (status) {
			restore_and_record_arg(t, status, &iter);
			r.ecx = (uintptr_t)status;
		} else {
			record_noop_data(t);
		}
		if (rusage) {
			restore_and_record_arg(t, rusage, &iter);
			r.esi = (uintptr_t)rusage;
		} else if (SYS_wait4 == syscall) {
			record_noop_data(t);
		}
		t->set_regs(r);

		finish_restoring_scratch(t, iter, &data);
		break;
	}

	case SYS_waitid: {
		siginfo_t* infop = pop_arg_ptr<siginfo_t>(t);
		byte* iter;
		void* data = start_restoring_scratch(t, &iter);

		struct user_regs_struct r = t->regs();
		if (infop) {
			restore_and_record_arg(t, infop, &iter);
			r.edx = (uintptr_t)infop;
		} else {
			record_noop_data(t);
		}
		t->set_regs(r);

		finish_restoring_scratch(t, iter, &data);
		break;
	}

	/**
	 * ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
	 * The writev() function writes iovcnt buffers of data described by iov
	 * to the file associated with the file descriptor fd ("gather output").
	 */
	SYS_REC0(writev);

	case SYS_rrcall_init_buffers:
		init_buffers(t, NULL, SHARE_DESCHED_EVENT_FD);
		break;

	case SYS_rrcall_monkeypatch_vdso:
		monkeypatch_vdso(t);
		break;

	default:
		print_register_file_tid(t);
		fatal("Unknown syscall %s(%d)", syscallname(syscall), syscall);
		break;		/* not reached */
	}
}
