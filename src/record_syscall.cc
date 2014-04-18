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
#include <sys/sysctl.h>
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

	t->record_remote(buf, len);
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
	assert(t->ev().type() == EV_SYSCALL);

	while (!t->ev().Syscall().saved_args.empty()) {
		t->ev().Syscall().saved_args.pop();
	}
	t->ev().Syscall().tmp_data_ptr = t->scratch_ptr;
	t->ev().Syscall().tmp_data_num_bytes = -1;
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
	t->ev().Syscall().saved_args.push(argp);
}

/**
 * Reset scratch state for |t|, because scratch can't be used for
 * |event|.  Log a warning as well.
 */
static int abort_scratch(Task* t, const char* event)
{
	int num_bytes = t->ev().Syscall().tmp_data_num_bytes;

	assert(t->ev().Syscall().tmp_data_ptr == t->scratch_ptr);

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

	assert(t->ev().Syscall().tmp_data_ptr == t->scratch_ptr);

	t->ev().Syscall().tmp_data_num_bytes = (scratch_end - scratch_start);
	return (0 <= t->ev().Syscall().tmp_data_num_bytes
		&& t->ev().Syscall().tmp_data_num_bytes <= t->scratch_size);
}

/**
 * Return nonzero if it's OK to context-switch away from |t| for its
 * ipc call.  If so, prepare any required scratch buffers for |t|.
 */
static int prepare_ipc(Task* t, int would_need_scratch)
{
	int call = t->regs().ebx;
	byte* scratch = would_need_scratch ?
			(byte*)t->ev().Syscall().tmp_data_ptr : nullptr;

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
			(byte*)t->ev().Syscall().tmp_data_ptr : nullptr;
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
	t->ev().Syscall().tmp_data_ptr =
		(byte*)t->syscallbuf_child +
		(rec->extra_data - (byte*)t->syscallbuf_hdr);
	/* |rec->size| is the entire record including extra data; we
	 * just care about the extra data here. */
	t->ev().Syscall().tmp_data_num_bytes = rec->size - sizeof(*rec);
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

static bool exec_file_supported(const string& filename)
{
	/* All this function does is reject 64-bit ELF binaries. Everything
	   else we (optimistically) indicate support for. Missing or corrupt
	   files will cause execve to fail normally. When we support 64-bit,
	   this entire function can be removed. */
	int fd = open(filename.c_str(), O_RDONLY);
	if (fd < 0) {
		return true;
	}
	char header[5];
	bool ok = true;
	if (read(fd, header, sizeof(header)) == sizeof(header)) {
		if (header[0] == ELFMAG0 && header[1] == ELFMAG1 &&
		    header[2] == ELFMAG2 && header[3] == ELFMAG3 &&
		    header[4] == ELFCLASS64) {
			ok = false;
		}
	}
	close(fd);
	return ok;
}

int rec_prepare_syscall(Task* t, void** kernel_sync_addr, uint32_t* sync_val)
{
	int syscallno = t->ev().Syscall().no;
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
		scratch = (byte*)t->ev().Syscall().tmp_data_ptr;
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

	case SYS_sendfile64: {
		struct user_regs_struct r = t->regs();
		loff_t* offset = (loff_t*)r.edx;

		if (!would_need_scratch) {
			return 1;
		}

		push_arg_ptr(t, offset);
		if (offset) {
			loff_t* offset2 = (loff_t*)scratch;
			scratch += sizeof(*offset2);
			t->remote_memcpy(offset2, offset, sizeof(*offset2));
			r.edx = (uintptr_t)offset2;
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

	case SYS_execve: {
		struct user_regs_struct r =  t->regs();
		string filename = t->read_c_str((void*)r.ebx);
		// We can't use push_arg_ptr/pop_arg_ptr to save and restore
		// ebx because execs get special ptrace events that clobber
		// the trace event for this system call.
		t->exec_saved_ebx = r.ebx;
		uintptr_t end = r.ebx + filename.length();
		if (filename[0] != '/') {
			char buf[PATH_MAX];
			snprintf(buf, sizeof(buf),
			         "/proc/%d/cwd/%s", t->real_tgid(),
			         filename.c_str());
			filename = buf;
		}
		if (!exec_file_supported(filename)) {
			// Force exec to fail with ENOENT by advancing ebx to
			// the null byte
			r.ebx = end;
			t->set_regs(r);
		}
		return 0;
	}

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

	case SYS__sysctl: {
		struct __sysctl_args sysctl_args;
		void* args_ptr = (void*)t->regs().ebx;
		t->read_mem(args_ptr, &sysctl_args);

		push_arg_ptr(t, sysctl_args.oldval);
		push_arg_ptr(t, sysctl_args.oldlenp);
		return 0;
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
	t->record_local(nullptr, 0, nullptr);
}

void rec_prepare_restart_syscall(Task* t)
{
	int syscallno = t->ev().Syscall().no;
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
				       t->ev().Syscall().saved_args.top();
		struct timespec* rem2 = (struct timespec*)t->regs().ecx;

		if (rem) {
			t->remote_memcpy(rem, rem2, sizeof(*rem));
			t->record_remote(rem, sizeof(*rem));
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
	file.time = t->trace_time();
	file.tid = t->tid;
	file.start = t->scratch_ptr;
	file.end = (byte*)t->scratch_ptr + scratch_size;
	sprintf(file.filename,"scratch for thread %d",t->tid);
	t->ofstream() << file;

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
	void* scratch = t->ev().Syscall().tmp_data_ptr;
	ssize_t num_bytes = t->ev().Syscall().tmp_data_num_bytes;

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
	return !t->ev().Syscall().saved_args.empty();
}

/**
 * Return the replaced tracee argument pointer saved by the matching
 * call to |push_arg_ptr()|.
 */
template<typename T>
static T* pop_arg_ptr(Task* t)
{
	void* arg = t->ev().Syscall().saved_args.top();
	t->ev().Syscall().saved_args.pop();
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
	t->record_local(child_addr, num_bytes, parent_data);
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
	ssize_t diff = t->ev().Syscall().tmp_data_num_bytes - consumed;

	assert(t->ev().Syscall().tmp_data_ptr == t->scratch_ptr);
	assert_exec(t, !diff || (slack && diff > 0),
		    "Saved %d bytes of scratch memory but consumed %d",
		    t->ev().Syscall().tmp_data_num_bytes, consumed);
	if (slack) {
		debug("Left %d bytes unconsumed in scratch", diff);
	}
	assert_exec(t, t->ev().Syscall().saved_args.empty(),
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
	struct user_regs_struct r = t->regs();
	if (SYSCALL_FAILED(r.eax)) {
		if (r.ebx != t->exec_saved_ebx) {
			log_warn("Blocked attempt to execve 64-bit image (not yet supported by rr)");
			// Restore EBX, which we clobbered.
			r.ebx = t->exec_saved_ebx;
			t->set_regs(r);
		}
		return;
	}

	// XXX what does this signifiy?
	if (r.ebx != 0) {
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
	t->record_remote(rand_addr, 16);

	init_scratch_memory(t);
}

static void record_ioctl_data(Task *t, ssize_t num_bytes)
{
	void* param = (void*)t->regs().edx;
	t->record_remote(param, num_bytes);
}

/**
 * Record.the page above the top of |t|'s stack.  The SIOC* ioctls
 * have been observed to write beyond the end of tracees' stacks, as
 * if they had allocated scratch space for themselves.  All we can do
 * for now is try to record the scratch data.
 */
static void record_scratch_stack_page(Task* t)
{
	t->record_remote((byte*)t->sp() - page_size(), page_size());
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
		t->record_remote(ifr.ifr_data, sizeof(struct ethtool_cmd));
		return;
	}
	case SIOCGIFCONF: {
		struct ifconf ifconf;
		t->read_mem(param, &ifconf);

		record_scratch_stack_page(t);
		t->record_local(param, sizeof(ifconf), &ifconf);
		t->record_remote(ifconf.ifc_buf, ifconf.ifc_len);
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
		t->record_remote(buf, buf_size);
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
		t->record_remote(kludge.msgbuf, buf_size);
		return;
	}
	case MSGGET:
	case MSGSND:
		return;
	default:
		fatal("Unhandled IPC call %d", call);
	}
}

static void process_mmap(Task* t, int syscallno,
			 size_t length, int prot, int flags,
			 int fd, off_t offset_pages)
{
		size_t size = ceil_page_size(length);
		off64_t offset = offset_pages * 4096;

		if (SYSCALL_FAILED(t->regs().eax)) {
			// We purely emulate failed mmaps.
			return;
		}
		void* addr = (void*)t->regs().eax;
		if (flags & MAP_ANONYMOUS) {
			// Anonymous mappings are by definition not
			// backed by any file-like object, and are
			// initialized to zero, so there's no
			// nondeterminism to record.
			//assert(!(flags & MAP_UNINITIALIZED));
			t->vm()->map(addr, size, prot, flags, 0,
				     MappableResource::anonymous());
			return;
		}

		assert_exec(t, fd >= 0, "Valid fd required for file mapping");
		assert(!(flags & MAP_GROWSDOWN));

		struct mmapped_file file;
		// TODO: save a reflink copy of the resource to the
		// trace directory as |fs/[st_dev].[st_inode]|.  Then
		// we wouldn't have to care about looking up a name
		// for the resource.
		file.time = t->trace_time();
		file.tid = t->tid;
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
			off64_t end = (off64_t)file.stat.st_size - offset;
			t->record_remote(addr, min(end, (off64_t)size));
		}
		t->ofstream() << file;

		t->vm()->map(addr, size, prot, flags, offset,
			     MappableResource(FileId(file.stat),
					      file.filename));
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
		t->record_remote(args.addrlen, sizeof(*args.addrlen));
		t->record_remote(args.addr, len);
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
				t->record_remote(buf, nrecvd);
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
			t->record_remote(args.buf, recvdlen);
		} else {
			record_noop_data(t);
		}
		if (args.src_addr) {
			socklen_t addrlen;
			t->read_mem(args.addrlen, &addrlen);

			t->record_remote(args.addrlen, sizeof(*args.addrlen));
			t->record_remote(args.src_addr, addrlen);
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
		t->record_local(args.msg, sizeof(tmpmsg), &msg);

		if (msg.msg_name) {
			t->remote_memcpy(msg.msg_name, tmpmsg.msg_name,
					 tmpmsg.msg_namelen);
		}
		t->record_remote(msg.msg_name, msg.msg_namelen);

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

			t->record_remote(iov->iov_base, iov->iov_len);
		}

		if (msg.msg_control) {
			t->remote_memcpy(msg.msg_control, tmpmsg.msg_control,
					 tmpmsg.msg_controllen);
		}
		t->record_remote(msg.msg_control, msg.msg_controllen);

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
		t->record_remote(args.optlen, sizeof(*args.optlen));
		t->record_remote(args.optval, optlen);
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
		t->record_remote(args.sv, 2 * sizeof(*args.sv));
		return;
	}

	default:
		fatal("Unknown socketcall %d", call);
	}
}

static void before_syscall_exit(Task* t, int syscallno)
{
	t->maybe_update_vm(syscallno, STATE_SYSCALL_EXIT);

	switch (syscallno) {
 	case SYS_sched_setaffinity: {
		if (SYSCALL_FAILED(t->regs().eax)) {
			// Nothing to do
			return;
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
		return;
	}
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
		return;
	}
	case SYS_set_tid_address:
		t->set_tid_addr((void*)t->regs().ebx);
		return;

	case SYS_sigaction:
	case SYS_rt_sigaction:
		// TODO: SYS_signal, SYS_sigaction
		t->update_sigaction();
		return;

	case SYS_sigprocmask:
	case SYS_rt_sigprocmask:
		t->update_sigmask();
		return;
	}
}

void rec_process_syscall(Task *t)
{
	int syscallno = t->ev().Syscall().no;

	debug("%d: processing syscall: %s(%d) -- time: %u",
	      tid, syscallname(syscallno), call, get_global_time());

	before_syscall_exit(t, syscallno);

	if (const struct syscallbuf_record* rec = t->desched_rec()) {
		assert(t->ev().Syscall().tmp_data_ptr != t->scratch_ptr);

		t->record_local(t->ev().Syscall().tmp_data_ptr,
				t->ev().Syscall().tmp_data_num_bytes,
				(byte*)rec->extra_data);
		return;
	}

	switch (syscallno) {
		// These macros are used to generate code that
		// processes the "regular" syscalls.  Irregular
		// syscalls are implemented by hand-written case
		// statements below.
#define SYSCALL_DEF0(_call, _)			\
	case SYS_##_call:			\
		break;
#define SYSCALL_DEF1(_call, _, _t0, _r0)				\
	case SYS_##_call:						\
		t->record_remote((void*)t->regs()._r0, sizeof(_t0));	\
		break;
#define SYSCALL_DEF1_DYNSIZE(_call, _, _s0, _r0)			\
	case SYS_##_call:						\
		t->record_remote((void*)t->regs()._r0, _s0);		\
		break;
#define SYSCALL_DEF1_STR(_call, _, _r0)					\
	case SYS_##_call:						\
		t->record_remote_str((void*)t->regs()._r0);		\
		break;
#define SYSCALL_DEF2(_call, _, _t0, _r0, _t1, _r1)			\
	case SYS_##_call:						\
		t->record_remote((void*)t->regs()._r0, sizeof(_t0));	\
		t->record_remote((void*)t->regs()._r1, sizeof(_t1));	\
		break;
#define SYSCALL_DEF3(_call, _, _t0, _r0, _t1, _r1, _t2, _r2)		\
	case SYS_##_call:						\
		t->record_remote((void*)t->regs()._r0, sizeof(_t0));	\
		t->record_remote((void*)t->regs()._r1, sizeof(_t1));	\
		t->record_remote((void*)t->regs()._r2, sizeof(_t2));	\
		break;
#define SYSCALL_DEF4(_call, _, _t0, _r0, _t1, _r1, _t2, _r2, _t3, _r3)	\
	case SYS_##_call:						\
		t->record_remote((void*)t->regs()._r0, sizeof(_t0));	\
		t->record_remote((void*)t->regs()._r1, sizeof(_t1));	\
		t->record_remote((void*)t->regs()._r2, sizeof(_t2));	\
		t->record_remote((void*)t->regs()._r3, sizeof(_t3));	\
		break;
#define SYSCALL_DEF_IRREG(_call)	// manually implemented below

#include "syscall_defs.h"

#undef SYSCALL_DEF0
#undef SYSCALL_DEF1
#undef SYSCALL_DEF1_STR
#undef SYSCALL_DEF2
#undef SYSCALL_DEF3
#undef SYSCALL_DEF4
#undef SYSCALL_DEF_IRREG

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

		new_task->push_event(SyscallEvent(syscallno));

		/* record child id here */
		new_task->record_remote((void*)t->regs().edx, sizeof(pid_t));
		new_task->record_remote((void*)t->regs().esi, sizeof(pid_t));

		new_task->record_remote((void*)new_task->regs().edi,
					sizeof(struct user_desc));
		new_task->record_remote((void*)new_task->regs().edx,
					sizeof(pid_t));
		new_task->record_remote((void*)new_task->regs().esi,
					sizeof(pid_t));

		new_task->pop_syscall();

		init_scratch_memory(new_task);
		// The new tracee just "finished" a clone that was
		// started by its parent.  It has no pending events,
		// so it can be context-switched out.
		new_task->switchable = 1;

		break;
	}
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
		} else {
			record_noop_data(t);
		}
		finish_restoring_scratch(t, iter, &data);
		break;
	}
	case SYS_execve:
		process_execve(t);
		break;

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
			t->record_remote((void*)t->regs().edx,
					 sizeof(struct flock));
			break;

		case F_SETLK:
		case F_SETLKW:
			break;

		case F_GETLK64:
			t->record_remote((void*)t->regs().edx,
					 sizeof(struct flock64));
			break;

		case F_SETLK64:
		case F_SETLKW64:
			break;

		case F_GETOWN_EX:
			t->record_remote((void*)t->regs().edx,
					 sizeof(struct f_owner_ex));
			break;

		default:
			fatal("Unknown fcntl %d", cmd);
		}
		break;
	}
	case SYS_futex:	{
		t->record_remote((void*)t->regs().ebx, sizeof(int));
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
			t->record_remote((void*)t->regs().edi, sizeof(int));
			break;

		default:
			fatal("Unknown futex op %d", op);
		}

		break;
	}
	case SYS_getxattr:
	case SYS_lgetxattr:
	case SYS_fgetxattr: {
		ssize_t len = t->regs().eax;
		void* value = (void*)t->regs().edx;

		if (len > 0) {
			t->record_remote(value, len);
		} else {
			record_noop_data(t);
		}
		break;
	}
	case SYS_ioctl:
		process_ioctl(t, t->regs().ecx);
		break;

	case SYS_ipc:
		process_ipc(t, t->regs().ebx);
		break;

	case SYS_mmap: {
		struct mmap_arg_struct args;
		t->read_mem((void*)t->regs().ebx, &args);
		process_mmap(t, syscallno, args.len,
			     args.prot, args.flags, args.fd,
			     args.offset / 4096);
		break;
	}
	case SYS_mmap2:
		process_mmap(t, syscallno, t->regs().ecx,
			     t->regs().edx, t->regs().esi,
			     t->regs().edi, t->regs().ebp);
		break;

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
	case SYS_quotactl: {
		 int cmd = t->regs().ebx & SUBCMDMASK;
		 void* addr = (void*)t->regs().esi;
		 switch (cmd) {
		 case Q_GETQUOTA:
		 	 t->record_remote(addr, sizeof(struct dqblk));
		 	 break;
		 case Q_GETINFO:
		 	 t->record_remote(addr, sizeof(struct dqinfo));
		 	 break;
		 case Q_GETFMT:
		 	 t->record_remote(addr, 4/*FIXME: magic number*/);
		 	 break;
		 case Q_SETQUOTA:
		 	 fatal("Trying to set disk quota usage, this may interfere with rr recording");
			 // not reached
		 default:
			 // TODO: some of these may need to be
			 // recorded ...
			 break;
		 }
		 break;
	}
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
				t->record_remote(buf, nread);
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
	case SYS_recvmmsg: {
		struct mmsghdr* msg = (struct mmsghdr*)t->regs().ecx;
		ssize_t nmmsgs = t->regs().eax;
		int i;

		for (i = 0; i < nmmsgs; ++i, ++msg) {
			record_struct_mmsghdr(t, msg);
		}
		break;
	}
	case SYS_sendfile64: {
		loff_t* offset = pop_arg_ptr<loff_t>(t);
		byte* iter;
		void* data = start_restoring_scratch(t, &iter);

		struct user_regs_struct r = t->regs();
		if (offset) {
			restore_and_record_arg(t, offset, &iter);
			r.edx = (uintptr_t)offset;
		} else {
			record_noop_data(t);
		}

		t->set_regs(r);
		finish_restoring_scratch(t, iter, &data);
		break;
	}
	case SYS_sendmmsg: {
		struct mmsghdr* msg = (struct mmsghdr*)t->regs().ecx;
		ssize_t nmmsgs = t->regs().eax;
		int i;

		/* Record the outparam msg_len fields. */
		for (i = 0; i < nmmsgs; ++i, ++msg) {
			t->record_remote(&msg->msg_len, sizeof(msg->msg_len));
		}
		break;
	}
	case SYS_socketcall:
		process_socketcall(t, t->regs().ebx, (void*)t->regs().ecx);
		break;

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
	case SYS__sysctl: {
		size_t* oldlenp = pop_arg_ptr<size_t>(t);
		void* oldval = pop_arg_ptr<void>(t);
		size_t oldlen;
		t->read_mem(oldlenp, &oldlen);

		t->record_remote(oldlenp, sizeof(size_t));
		t->record_remote(oldval, oldlen);
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
	case SYS_waitpid:
	case SYS_wait4: {
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
		} else if (SYS_wait4 == syscallno) {
			record_noop_data(t);
		}
		t->set_regs(r);

		finish_restoring_scratch(t, iter, &data);
		break;
	}
	case SYS_write:
	case SYS_writev:
		break;

	case SYS_rrcall_init_buffers:
		init_buffers(t, nullptr, SHARE_DESCHED_EVENT_FD);
		break;

	case SYS_rrcall_monkeypatch_vdso:
		monkeypatch_vdso(t);
		break;

	default:
		print_register_file_tid(t);
		fatal("Unhandled syscall %s(%d)",
		      syscallname(syscallno), syscallno);
		break;		/* not reached */
	}
}
