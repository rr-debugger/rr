/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "syscall_buffer.h"

/**
 * Buffer syscalls, so that rr can process the entire buffer with one
 * trap instead of a trap per call.
 *
 * This file is compiled into a dso that's PRELOADed in recorded
 * applications.  The dso replaces libc syscall wrappers with our own
 * implementation that saves nondetermistic outparams in a fixed-size
 * buffer.  When the buffer is full or the recorded application
 * invokes an un-buffered syscall or receives a signal, we trap to rr
 * and it records the state of the buffer.
 *
 * During replay, rr simply refills the buffer with the recorded data
 * when it reaches the "flush-buffer" events that were recorded.  Then
 * rr emulates each buffered syscall, and the code here restores the
 * client data from the refilled buffer.
 *
 * The crux of the implementation here is to selectively ptrace-trap
 * syscalls.  The normal (un-buffered) syscalls generate a ptrace
 * trap, and the buffered syscalls trap directly to the kernel.  This
 * is implemented with a seccomp-bpf which examines the syscall and
 * decides how to handle it (see seccomp-bpf.h).
 *
 * Because this code runs in the tracee's address space and overrides
 * libc symbols, the code is rather delicate.  The following rules
 * must be followed
 *
 * o No rr headers (other than seccomp-bpf.h) may be included
 * o All syscalls invoked by this code must be called directly, not
 *   through libc wrappers (which this file may itself wrap)
 */

#include <fcntl.h>
#include <limits.h>
#include <link.h>
#include <linux/futex.h>
#include <linux/net.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syscall.h>
#include <sys/epoll.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

/* NB: don't include any other local headers here. */
#include "seccomp-bpf.h"

typedef unsigned char byte;

/* Nonzero after we've installed the filter. */
static int is_seccomp_bpf_installed;

static __thread byte* buffer = NULL;
/* This is used to support the buffering of "may-block" system calls.
 * The problem that needs to be addressed can be introduced with a
 * simple example; assume that we're buffering the "read" and "write"
 * syscalls.
 *
 *  o (Tasks W and R set up a synchronous-IO pipe open between them; W
 *    "owns" the write end of the pipe; R owns the read end; the pipe
 *    buffer is full)
 *  o Task W invokes the write syscall on the pipe
 *  o Since write is a buffered syscall, the seccomp filter traps W
 *    directly to the kernel; there's no trace event for W delivered
 *    to rr.
 *  o The pipe is full, so W is descheduled by the kernel because W
 *    can't make progress.
 *  o rr thinks W is still running and doesn't schedule R.
 *
 * At this point, progress in the recorded application can only be
 * made by scheduling R, but no one tells rr to do that.  Oops!
 *
 * Thus enter the "desched counter".  It's a perf_event for the "sw
 * context switches" event (which, more precisely, is "sw deschedule";
 * it counts schedule-out, not schedule-in).  We program the counter
 * to deliver SIGIO to this task when there's new counter data
 * available.  And we set up the "sample period", how many descheds
 * are triggered before SIGIO is delivered, to be "1".  This means
 * that when the counter is armed, the next desched (i.e., the next
 * time the desched counter is bumped up) of this task will deliver
 * SIGIO to it.  And signal delivery always generates a ptrace trap,
 * so rr can deduce that this task was descheduled and schedule
 * another.
 *
 * The description above is sort of an idealized view; there are
 * numerous implementation details that are documented in
 * handle_signal.c, where they're dealt with. */
static __thread int desched_counter_fd;

/**
 * Return a pointer to the buffer header, which happens to occupy the
 * initial bytes in the mapped region.
 */
static struct syscallbuf_hdr* buffer_hdr()
{
	return (struct syscallbuf_hdr*)buffer;
}

/**
 * Return a pointer to the byte just after the last valid syscall record in
 * the buffer.
 */
static byte* buffer_last()
{
	return (byte*)next_record(buffer_hdr());
}

/**
 * Return a pointer to the byte just after the very end of the mapped
 * region.
 */
static byte* buffer_end()
{
	return buffer + SYSCALLBUF_BUFFER_SIZE;
}

/* The following are wrappers for the syscalls invoked by this library
 * itself.  These syscalls will generate ptrace traps. */

static int traced_fcntl(int fd, int cmd, ...)
{
	va_list ap;
	void *arg;

	va_start(ap, cmd);
	arg = va_arg(ap, void*);
	va_end(ap);

	return syscall(SYS_fcntl64, fd, cmd, arg);
}

static pid_t traced_getpid()
{
	return syscall(SYS_getpid);
}

static pid_t traced_gettid()
{
	return syscall(SYS_gettid);
}

static int traced_perf_event_open(struct perf_event_attr *attr,
				  pid_t pid, int cpu, int group_fd,
				  unsigned long flags)
{
    return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static int traced_prctl(int option, unsigned long arg2, unsigned long arg3,
		     unsigned long arg4, unsigned long arg5)
{
	return syscall(SYS_prctl, option, arg2, arg3, arg4, arg4);
}

static int traced_raise(int sig)
{
	return syscall(SYS_kill, traced_getpid(), sig);
}

static int traced_sigprocmask(int how, const sigset_t* set, sigset_t* oldset)
{
	/* Warning: expecting this to only change the mask of the
	 * current task is a linux-ism; POSIX leaves the behavior
	 * undefined. */
	return syscall(SYS_rt_sigprocmask, set, oldset);
}

static ssize_t traced_write(int fd, const void* buf, size_t count)
{
	return syscall(SYS_write, fd, buf, count);
}

/* We can't use the rr logging helpers because they rely on libc
 * syscall-invoking functions, so roll our own here.
 *
 * XXX just use these for all logging? */

__attribute__((format(printf, 1, 2)))
static void logmsg(const char* msg, ...)
{
  va_list args;
  char buf[1024];
  int len;

  va_start(args, msg);
  len = vsnprintf(buf, sizeof(buf) - 1, msg, args);
  va_end(args);

  traced_write(STDERR_FILENO, buf, len);
}

#ifndef NDEBUG
# define assert(cond)							\
	do {								\
		if (!(cond)) {						\
			logmsg("%s:%d: Assertion " #cond " failed.",	\
			       __FILE__, __LINE__);			\
			traced_raise(SIGABRT);				\
		}							\
	} while (0)
#else
# define assert(cond) ((void)0)
#endif

#define fatal(msg, ...)							\
	do {								\
		logmsg("[FATAL] (%s:%d: errno: %s) " msg "\n",		\
		       __FILE__, __LINE__, strerror(errno), ##__VA_ARGS__); \
		assert("Bailing because of fatal error" && 0);		\
	} while (0)

#define log_info(msg, ...)					\
	logmsg("[INFO] (%s:%d) " msg "\n", __FILE__, __LINE__, ##__VA_ARGS__)


/* Helpers for invoking untraced syscalls, which do *not* generate
 * ptrace traps.
 *
 * XXX make a nice assembly helper like libc's |syscall()|? */
static int untraced_syscall(int syscall, long arg0, long arg1, long arg2,
			    long arg3, long arg4)
{
	int ret;
	__asm__ __volatile__("call _untraced_syscall_entry_point"
			     : "=a"(ret)
			     : "0"(syscall), "b"(arg0), "c"(arg1), "d"(arg2),
			       "S"(arg3), "D"(arg4));
	return ret;
}
#define untraced_syscall5(no, a0, a1, a2, a3, a4)			\
	untraced_syscall(no, (uintptr_t)a0, (uintptr_t)a1, (uintptr_t)a2, (uintptr_t)a3, (uintptr_t)a4)
#define untraced_syscall4(no, a0, a1, a2, a3)		\
	untraced_syscall5(no, a0, a1, a2, a3, 0)
#define untraced_syscall3(no, a0, a1, a2)	\
	untraced_syscall4(no, a0, a1, a2, 0)
#define untraced_syscall2(no, a0, a1)		\
	untraced_syscall3(no, a0, a1, 0)
#define untraced_syscall1(no, a0)		\
	untraced_syscall2(no, a0, 0)
#define untraced_syscall0(no)			\
	untraced_syscall1(no, 0)

/**
 * The seccomp filter is set up so that system calls made through
 * _untraced_syscall_entry_point are always allowed without triggering
 * ptrace. This gives us a convenient way to make non-traced system calls.
 */
__asm__(".text\n\t"
	"_untraced_syscall_entry_point:\n\t"
	"int $0x80\n\t"
	"_untraced_syscall_entry_point_ip:\n\t"
	"ret");

static void* get_untraced_syscall_entry_point()
{
    void *ret;
    __asm__ __volatile__(
	    "call _get_untraced_syscall_entry_point__pic_helper\n\t"
	    "_get_untraced_syscall_entry_point__pic_helper: pop %0\n\t"
	    "addl $(_untraced_syscall_entry_point_ip - _get_untraced_syscall_entry_point__pic_helper),%0"
	    : "=a"(ret));
    return ret;
}

/**
 * Do what's necessary to map the shared syscall buffer region in the
 * caller's address space and return the mapped region.
 * |untraced_syscall_ip| lets rr know where our untraced syscalls will
 * originate from.  |addr| is the address of the control socket the
 * child expects to connect to.  |msg| is a pre-prepared IPC that can
 * be used to share fds; |fdptr| is a pointer to the control-message
 * data buffer where the fd number being shared will be stored.
 * |args_vec| provides the tracer with preallocated space to make
 * socketcall syscalls.
 *
 * This is a "magic" syscall implemented by rr.
 */
static void* rrcall_init_syscall_buffer(void* untraced_syscall_ip,
					struct sockaddr_un* addr,
					struct msghdr* msg, int* fdptr,
					struct socketcall_args* args_vec)
{
	return (void*)syscall(RRCALL_init_syscall_buffer, untraced_syscall_ip,
			      addr, msg, fdptr, args_vec);
}

/**
 * This installs the actual filter which examines the callsite and
 * determines whether it will be ptraced or handled by the
 * intercepting library
 */
static void install_syscall_filter()
{
	void* protected_call_start = get_untraced_syscall_entry_point();
	struct sock_filter filter[] = {
		/* Allow all system calls from our protected_call
		 * callsite */
		ALLOW_SYSCALLS_FROM_CALLSITE((uintptr_t)protected_call_start),
		/* All the rest are handled in rr */
		TRACE_PROCESS,
	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};

	log_info("Initializing syscall buffer: protected_call_start = %p",
		protected_call_start);

	if (traced_prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		fatal("prctl(NO_NEW_PRIVS) failed, SECCOMP_FILTER is not available: your kernel is too old.  Use `record -n` to disable the filter.");
	}

	/* Note: the filter is installed only for record. This call
	 * will be emulated in the replay */
	if (traced_prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
			 (uintptr_t)&prog, 0, 0)) {
		fatal("prctl(SECCOMP) failed, SECCOMP_FILTER is not available: your kernel is too old.  Use `record -n` to disable the filter.");
	}
	/* anything that happens from this point on gets filtered! */
}

/**
 * Return a counter that generates a SIGIO targeted at this task every
 * time the task is descheduled |nr_descheds| times.
 */
static int open_desched_event_counter(size_t nr_descheds)
{
	struct perf_event_attr attr;
	int fd;
	struct f_owner_ex own;

	memset(&attr, 0, sizeof(attr));
	attr.size = sizeof(attr);
	attr.type = PERF_TYPE_SOFTWARE;
	attr.config = PERF_COUNT_SW_CONTEXT_SWITCHES;
	attr.disabled = 1;
	attr.sample_period = nr_descheds;

	fd = traced_perf_event_open(&attr, 0/*self*/, -1/*any cpu*/, -1, 0);
	if (0 > fd) {
		fatal("Failed to perf_event_open(cs, period=%u)", nr_descheds);
	}
	if (traced_fcntl(fd, F_SETFL, O_ASYNC)) {
		fatal("Failed to fcntl(O_ASYNC) the desched counter");
	}
	own.type = F_OWNER_TID;
	own.pid = traced_gettid();
	if (traced_fcntl(fd, F_SETOWN_EX, &own)) {
		fatal("Failed to fcntl(SETOWN_EX) the desched counter to this");
	}
	if (traced_fcntl(fd, F_SETSIG, SIGIO)) {
		fatal("Failed to fcntl(SETSIG, SIGIO) the desched counter");
	}

	return fd;
}

static void set_up_buffer()
{
	struct sockaddr_un addr;
	struct msghdr msg;
	struct iovec data;
	int msgbuf;
	struct cmsghdr* cmsg;
	int* msg_fdptr;
	int* cmsg_fdptr;
	char cmsgbuf[CMSG_SPACE(sizeof(*cmsg_fdptr))];
	struct socketcall_args args_vec;

	assert(!buffer);

	/* NB: we want this setup emulated during replay. */
	desched_counter_fd = open_desched_event_counter(1);

	/* Prepare arguments for rrcall.  We do this in the tracee
	 * just to avoid some hairy IPC to set up the arguments
	 * remotely from the traceer; this isn't strictly
	 * necessary. */
	prepare_syscallbuf_socket_addr(&addr, traced_gettid());

	memset(&msg, 0, sizeof(msg));
	msg_fdptr = &msgbuf;
	data.iov_base = msg_fdptr;
	data.iov_len = sizeof(msgbuf);
	msg.msg_iov = &data;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(*cmsg_fdptr));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg_fdptr = (int*)CMSG_DATA(cmsg);

	/* Set the "fd parameter" in the message buffer, which we send
	 * to let the other side know the local fd number we shared to
	 * it. */
	*msg_fdptr = desched_counter_fd;
	/* Set the "fd parameter" in the cmsg buffer, which is the one
	 * the kernel parses, dups, then sets to the fd number
	 * allocated in the other process. */
	*cmsg_fdptr = desched_counter_fd;
	{
		sigset_t mask, oldmask;
		/* Create a "critical section" that can't be
		 * interrupted by signals.  rr doesn't want to deal
		 * with signals while injecting syscalls into us. */
		sigfillset(&mask);
		traced_sigprocmask(SIG_BLOCK, &mask, &oldmask);

		/* Trap to rr: let the magic begin!  We've prepared
		 * the buffer so that it's immediately ready to be
		 * sendmsg()'d to rr to share the desched counter to
		 * it (under rr's control).  rr can further use the
		 * buffer to share more fd's to us. */
		buffer = rrcall_init_syscall_buffer(
			get_untraced_syscall_entry_point(),
			&addr, &msg, cmsg_fdptr, &args_vec);
		/* rr initializes the buffer header. */

		/* End "critical section". */
		traced_sigprocmask(SIG_SETMASK, &oldmask, NULL);
	}
}

/**
 * After a fork(), the new child will still share the buffer mapping
 * with its parent.  That's obviously very bad.  Pretend that we don't
 * know about the old buffer, so that the next time a buffered syscall
 * is hit, we map a new buffer.
 */
static void drop_buffer()
{
	buffer = NULL;
}

/**
 * Initialize the library:
 * 1. Install filter-by-callsite (once for all threads)
 * 2. Make subsequent threads call init()
 * 3. Open and mmap the recording cache, shared with rr (once for
 *    every thread)
 *
 * Remember: init() will only be called if the process uses at least
 * one of the library's intercepted functions.
 */
static void init()
{
	if (!is_seccomp_bpf_installed) {
		install_syscall_filter();
		is_seccomp_bpf_installed = 1;
		pthread_atfork(NULL, NULL, drop_buffer);
	}
	set_up_buffer();
}

/**
 * Wrappers start here.
 *
 * How wrappers operate:
 *
 * 1. The syscall is intercepted by the wrapper function.
 * 2. A new record is prepared on the buffer. A record is composed of:
 * 		[the syscall number]
 * 		[the overall size in bytes of the record]
 * 		[the return value]
 * 		[other syscall output, if such exists]
 *    If the buffer runs out of space, we turn this into a
 *    non-intercepted system call which is handled by rr directly,
 *    flushing the buffer and aborting these steps.  Note: these
 *    records will be written AS-IS to the raw file, and a succinct
 *    line will be written to the trace file (without register
 *    content, etc.)
 * 3. Then, the syscall wrapper code redirects all potential output
 *    for the syscall to the record (and corrects the overall size of
 *    the record while it does so).
 * 4. The syscall is invoked directly via assembly.
 * 5. The syscall output, written on the buffer, is copied to the
 *    original pointers provided by the user.  Take notice that this
 *    part saves us the injection of the data on replay, as we only
 *    need to push the data to the buffer and the wrapper code will
 *    copy it to the user address for us.
 * 6. The first 3 parameters of the record are put in (return value
 *    and overall size are known now)
 * 7. buffer[0] is updated.
 * 8. errno is set.
 */

/**
 * Call this and save the result at the start of every system call we
 * want to buffer. The result is a pointer into the record space. You
 * can add to this pointer to allocate space in the trace record.
 * However, do not read or write through this pointer until
 * can_buffer_syscall has been called.  And you *must* call
 * can_buffer_syscall after this is called, otherwise buffering state
 * will be inconsistent between syscalls.  Usage should look something
 * like
 *
 *   // If there's something at runtime that should stop buffering the
 *   // syscall, like an unknown parameter, bail.
 *   if (!try_to_buffer()) {
 *       goto fallback_trace;
 *   }
 *
 *   // Reserve buffer space for the recorded syscall and any other
 *   // required internal bookkeeping data.
 *   void* ptr = prep_syscall();
 *
 *   // If the syscall requires recording any extra data, reserve
 *   // space for it too.
 *   ptr += sizeof(extra_syscall_data);
 *
 *   // If there's not enough space, bail.
 *   if (!start_commit_buffered_syscall(SYS_foo, ptr, WILL_ARM_DESCHED_EVENT)) {
 *       goto fallback_trace;
 *   }
 *
 *   // Since this syscall may block, arm/disarm the desched
 *   // notification.
 *   arm_desched_notification();
 *   untraced_syscall(...);
 *   disarm_desched_notification();
 *
 *   // Store the extra_syscall_data that space was reserved for
 *   // above.
 *
 *   // Update the buffer.
 *   return commit_syscall(..., DID_DISARM_DESCHED_EVENT);
 *
 * fallback_trace:
 *   return syscall(...);  // traced
 */
static void* prep_syscall()
{
	if (!buffer) {
		init();
	}
	if (buffer_hdr()->locked) {
		/* We may be reentering via a signal handler. Return
		 * an invalid pointer.
		 */
		return NULL;
	}
	/* We don't need to worry about a race between testing
	 * |locked| and setting it here. rr recording is responsible
	 * for ensuring signals are not delivered during
	 * syscall_buffer prologue and epilogue code.
	 *
	 * XXX except for synchronous signals generated in the syscall
	 * buffer code, while reading/writing user pointers */
	buffer_hdr()->locked = 1;
	/* "Allocate" space for a new syscall record, not including
	 * syscall outparam data. */
	return buffer_last() + sizeof(struct syscallbuf_record);
}

/**
 * Return 1 if it's ok to proceed with buffering this system call.
 * Return 0 if we should trace the system call.
 * This must be checked before proceeding with the buffered system call.
 */
/* (Negative numbers so as to not be valid syscall numbers, in case
 * the |int| arguments below are passed in the wrong order.) */
enum { WILL_ARM_DESCHED_EVENT = -1,
       DISARMED_DESCHED_EVENT = -2,
       NO_DESCHED = -3 };
static int start_commit_buffered_syscall(int syscallno, void* record_end,
					 int notify_desched)
{
	void* record_start = buffer_last();
	void* stored_end =
		record_start + stored_record_size(record_end - record_start);
	struct syscallbuf_record* rec = record_start;

	if (stored_end < record_start + sizeof(struct syscallbuf_record)) {
		/* Either a catastrophic buffer overflow or
		 * we failed to lock the buffer. Just bail out. */
		return 0;
	}
	if (stored_end > (void*)buffer_end() - sizeof(struct syscallbuf_record)) {
		/* Buffer overflow.
		 * Unlock the buffer and then execute the system call
		 * with a trap to rr.  Note that we reserve enough
		 * space in the buffer for the next prep_syscall(). */
		buffer_hdr()->locked = 0;
		return 0;
	}
	/* Store this breadcrumb so that the tracer can find out what
	 * syscall we're executing if our registers are in a weird
	 * state.  If we end up aborting this syscall, no worry, this
	 * will just be overwritten later.
	 *
	 * NBB: this *MUST* be set before the desched event is
	 * armed. */
	rec->syscallno = syscallno;
	rec->desched = NO_DESCHED != notify_desched;
	rec->size = record_end - record_start;
	return 1;
}

inline static void arm_desched_event()
{
	/* Don't trace the ioctl; doing so would trigger a flushing
	 * ptrace trap, which is exactly what this code is trying to
	 * avoid! :) Although we don't allocate extra space for these
	 * ioctl's, we do record that we called them; the replayer
	 * knows how to skip over them. */
	if (untraced_syscall3(SYS_ioctl, desched_counter_fd,
			      PERF_EVENT_IOC_ENABLE, 0)) {
		fatal("Failed to ENABLE counter %d", desched_counter_fd);
	}
}

inline static void disarm_desched_event()
{
	/* See above. */
	if (untraced_syscall3(SYS_ioctl, desched_counter_fd,
			      PERF_EVENT_IOC_DISABLE, 0)) {
		fatal("Failed to ENABLE counter %d", desched_counter_fd);
	}
}

static int update_errno_ret(int ret)
{
	/* EHWPOISON is the last known errno as of linux 3.9.5. */
	if (0 > ret && ret >= -EHWPOISON) {
		errno = -ret;
		ret = -1;
	}
	return ret;
}

/**
 * Commit the record for a buffered system call.
 * record_end can be adjusted downward from what was passed to
 * start_commit_buffered_syscall, if not all of the initially requested space is needed.
 * The result of this function should be returned directly by the
 * wrapper function.
 */
static int commit_syscall(int syscallno, void* record_end, int ret,
			  int disarmed_desched)
{
	void* record_start = buffer_last();
	struct syscallbuf_record* rec = record_start;
	struct syscallbuf_hdr* hdr = buffer_hdr();

	if (hdr->abort_commit) {
		/* We were descheduled in the middle of a may-block
		 * syscall, and it was recorded as a normal entry/exit
		 * pair.  So don't record the syscall in the buffer or
		 * replay will go haywire. */
		hdr->abort_commit = 0;
	} else {
		if (rec->syscallno != syscallno) {
			fatal("Record is for %d but trying to commit %d",
			      rec->syscallno, syscallno);
		}
		if (!((rec->desched
		       && DISARMED_DESCHED_EVENT == disarmed_desched)
		      || (!rec->desched
			  && NO_DESCHED == disarmed_desched))) {
			fatal("Mismatched arm/disarm-desched for %d",
			      rec->syscallno);
		}
		rec->ret = ret;
		hdr->num_rec_bytes += stored_record_size(rec->size);
	}
	buffer_hdr()->locked = 0;

	return update_errno_ret(ret);
}

/**
 * Copy |in| to |out|, watching for overflow on vulnerable fields.  If
 * overflow is observed, |errno| is set to EOVERFLOW and -1 is
 * returned.
 */
static int copy_to_stat(const struct stat64* in, struct stat* out)
{
#define COPY_CHECK_OVERFLOW(_lhs, _rhs)					\
	do {								\
		_lhs = _rhs;						\
		if (sizeof(_lhs) != sizeof(_rhs) && _lhs != _rhs) {	\
			errno = EOVERFLOW;				\
			return -1;					\
		}							\
	} while(0)
	/* XXX this is /really/ reaching deep into libc innards, but
	 * we don't have a choice ... */
	out->st_dev = in->st_dev;
	out->__pad1 = 0;
	COPY_CHECK_OVERFLOW(out->st_ino, in->st_ino);
	out->st_mode = in->st_mode;
	out->st_nlink = in->st_nlink;
	out->st_uid = in->st_uid;
	out->st_gid = in->st_gid;
	out->st_rdev = in->st_rdev;
	out->__pad2 = 0;
	COPY_CHECK_OVERFLOW(out->st_size, in->st_size);
	out->st_blksize = in->st_blksize;
	COPY_CHECK_OVERFLOW(out->st_blocks, in->st_blocks);
	out->st_atime = in->st_atime;
	out->st_mtime = in->st_mtime;
	out->st_ctime = in->st_ctime;
	out->__unused4 = 0;
	out->__unused5 = 0;
#undef COPY_CHECK_OVERFLOW
	return 0;
}

static int stat_something(int syscallno, int vers, unsigned long what,
			  struct stat64* buf)
{
	/* Like open(), not arming the desched event because it's not
	 * needed for correctness, and there are no data to suggest
	 * whether it's a good idea perf-wise. */
	void* ptr = prep_syscall();
	struct stat64* buf2 = NULL;
	long ret;

	if (_STAT_VER_LINUX != vers) {
		fatal("Unhandled stat ABI version %d", vers);		
	}

	if (buf) {
		buf2 = ptr;
		ptr += sizeof(*buf2);
	}
	if (!start_commit_buffered_syscall(syscallno, ptr, NO_DESCHED)) {
		return syscall(syscallno, what, buf);
	}
	ret = untraced_syscall2(syscallno, what, buf2);
	if (buf2) {
		memcpy(buf, buf2, sizeof(*buf));
	}
	return commit_syscall(syscallno, ptr, ret, NO_DESCHED);
}

/**
 * Make the traced socketcall |call| with the given args.
 *
 * NB: this helper *DOES* update errno and massage the return value.
 */
int traced_socketcall(int call, long a0, long a1, long a2, long a3, long a4)
{
	unsigned long args[] = { a0, a1, a2, a3, a4 };
	return syscall(SYS_socketcall, call, args);
}
#define traced_socketcall5(no, a0, a1, a2, a3, a4)			\
	traced_socketcall(no, (uintptr_t)a0, (uintptr_t)a1, (uintptr_t)a2, (uintptr_t)a3, (uintptr_t)a4)
#define traced_socketcall4(no, a0, a1, a2, a3)		\
	traced_socketcall5(no, a0, a1, a2, a3, 0)
#define traced_socketcall3(no, a0, a1, a2)	\
	traced_socketcall4(no, a0, a1, a2, 0)
#define traced_socketcall2(no, a0, a1)		\
	traced_socketcall3(no, a0, a1, 0)
#define traced_socketcall1(no, a0)		\
	traced_socketcall2(no, a0, 0)
#define traced_socketcall0(no)			\
	traced_socketcall1(no, 0)

/**
 * Make the *un*traced socketcall |call| with the given args.
 *
 * NB: this helper *DOES NOT* touch the raw return value from the
 * kernel.  Callers must update errno themselves.
 */
long untraced_socketcall(int call, long a0, long a1, long a2, long a3, long a4)
{
	unsigned long args[] = { a0, a1, a2, a3, a4 };
	return untraced_syscall2(SYS_socketcall, call, args);
}
#define untraced_socketcall5(no, a0, a1, a2, a3, a4)			\
	untraced_socketcall(no, (uintptr_t)a0, (uintptr_t)a1, (uintptr_t)a2, (uintptr_t)a3, (uintptr_t)a4)
#define untraced_socketcall4(no, a0, a1, a2, a3)	\
	untraced_socketcall5(no, a0, a1, a2, a3, 0)
#define untraced_socketcall3(no, a0, a1, a2)	\
	untraced_socketcall4(no, a0, a1, a2, 0)
#define untraced_socketcall2(no, a0, a1)	\
	untraced_socketcall3(no, a0, a1, 0)
#define untraced_socketcall1(no, a0)		\
	untraced_socketcall2(no, a0, 0)
#define untraced_socketcall0(no)		\
	untraced_socketcall1(no, 0)

/* Keep syscalls in alphabetical order, please. */

int access(const char* pathname, int mode)
{
	void* ptr = prep_syscall();
	long ret;

	if (!start_commit_buffered_syscall(SYS_access, ptr, NO_DESCHED)) {
		return syscall(SYS_access, pathname, mode);
 	}
	ret = untraced_syscall2(SYS_access, pathname, mode);
	return commit_syscall(SYS_access, ptr, ret, NO_DESCHED);
}

int clock_gettime(clockid_t clk_id, struct timespec* tp)
{
	void* ptr = prep_syscall();
	struct timespec *tp2 = NULL;
	long ret;

	/* Set it up so the syscall writes to the record cache. */
	if (tp) {
		tp2 = ptr;
		ptr += sizeof(struct timespec);
	}
	if (!start_commit_buffered_syscall(SYS_clock_gettime, ptr, NO_DESCHED)) {
		return syscall(SYS_clock_gettime, clk_id, tp);
 	}
	ret = untraced_syscall2(SYS_clock_gettime, clk_id, tp2);
	/* Now in the replay we can simply refill the recorded buffer
	 * data, emulate the syscalls, and this code will restore the
	 * recorded data to the outparams. */
	if (tp) {
		memcpy(tp, tp2, sizeof(struct timespec));
	}
	return commit_syscall(SYS_clock_gettime, ptr, ret, NO_DESCHED);
}

int close(int fd)
{
	void* ptr = prep_syscall();
	long ret;

	if (!start_commit_buffered_syscall(SYS_close, ptr, NO_DESCHED)) {
		return syscall(SYS_close, fd);
 	}
	ret = untraced_syscall1(SYS_close, fd);
	return commit_syscall(SYS_close, ptr, ret, NO_DESCHED);
}

int creat(const char* pathname, mode_t mode)
{
	/* Thus sayeth the man page:
	 *
	 *   creat() is equivalent to open() with flags equal to
	 *   O_CREAT|O_WRONLY|O_TRUNC. */
	return open(pathname, O_CREAT | O_TRUNC | O_WRONLY, mode);
}

static int fcntl0(int fd, int cmd)
{
	/* No zero-arg fcntl's are known to be may-block. */
	void* ptr = prep_syscall();
	long ret;

	if (!start_commit_buffered_syscall(SYS_fcntl64, ptr, NO_DESCHED)) {
		return syscall(SYS_fcntl64, fd, cmd);
 	}
	ret = untraced_syscall2(SYS_fcntl64, fd, cmd);
	return commit_syscall(SYS_fcntl64, ptr, ret, NO_DESCHED);
}

static int fcntl1(int fd, int cmd, int arg)
{
	/* No one-int-arg fcntl's are known to be may-block. */
	void* ptr = prep_syscall();
	long ret;

	if (!start_commit_buffered_syscall(SYS_fcntl64, ptr, NO_DESCHED)) {
		return syscall(SYS_fcntl64, fd, cmd, arg);
	}
	ret = untraced_syscall3(SYS_fcntl64, fd, cmd, arg);
	return commit_syscall(SYS_fcntl64, ptr, ret, NO_DESCHED);
}

static int fcntl_own_ex(int fd, int cmd, struct f_owner_ex* owner)
{
	/* The OWN_EX fcntl's aren't may-block. */
	void* ptr = prep_syscall();
	struct f_owner_ex* owner2 = NULL;
	long ret;

	if (owner) {
		owner2 = ptr;
		ptr += sizeof(*owner2);
	}
	if (!start_commit_buffered_syscall(SYS_fcntl64, ptr, NO_DESCHED)) {
		return syscall(SYS_fcntl64, fd, cmd, owner);
	}
	if (owner2) {
		memcpy(owner2, owner, sizeof(*owner2));
	}
	ret = untraced_syscall3(SYS_fcntl64, fd, cmd, owner2);
	if (owner2) {
		memcpy(owner, owner2, sizeof(*owner));
	}
	return commit_syscall(SYS_fcntl64, ptr, ret, NO_DESCHED);
}

static int fcntl_flock(int fd, int cmd, struct flock64* lock)
{
	void* ptr = prep_syscall();
	struct flock64* lock2 = NULL;
	long ret;

	if (lock) {
		lock2 = ptr;
		ptr += sizeof(*lock2);
	}
	if (!start_commit_buffered_syscall(SYS_fcntl64, ptr,
					   WILL_ARM_DESCHED_EVENT)) {
		return syscall(SYS_fcntl64, fd, cmd, lock);
	}

	if (lock2) {
		memcpy(lock2, lock, sizeof(*lock2));
	}

	arm_desched_event();
	ret = untraced_syscall3(SYS_fcntl64, fd, cmd, lock2);
	disarm_desched_event();

	if (lock2) {
		memcpy(lock, lock2, sizeof(*lock));
	}

	return commit_syscall(SYS_fcntl64, ptr, ret, DISARMED_DESCHED_EVENT);
}

int fcntl(int fd, int cmd, ... /* arg */)
{
	switch (cmd) {
	case F_DUPFD:
	case F_GETFD:
	case F_GETFL:
	case F_GETOWN:
		return fcntl0(fd, cmd);

	case F_SETFL:
	case F_SETFD:
	case F_SETOWN:
	case F_SETSIG:
	{
		va_list varg;
		int arg;

		va_start(varg, cmd);
		arg = va_arg(varg, int);
		va_end(varg);

		return fcntl1(fd, cmd, arg);
	}

	case F_GETOWN_EX:
	case F_SETOWN_EX:
	{
		va_list varg;
		struct f_owner_ex* owner;

		va_start(varg, cmd);
		owner = va_arg(varg, struct f_owner_ex*);
		va_end(varg);

		return fcntl_own_ex(fd, cmd, owner);
	}

	case F_GETLK64:
	case F_SETLK64:
	case F_SETLKW64:
	case F_GETLK:
	case F_SETLK:
	{
		va_list varg;
		struct flock64* lock;

		va_start(varg, cmd);
		lock = va_arg(varg, struct flock64*);
		va_end(varg);

		return fcntl_flock(fd, cmd, lock);
	}

	default:
		/* Unfortunately, we can't fall back on a traced
		 * fcntl, because we don't know how to interpret the
		 * args to set them up for the syscall. */
		fatal("Unhandled fcntl %d", cmd);
		return -1;	/* not reached */
	}
}

int __fxstat64(int vers, int fd, struct stat64* buf)
{
	return stat_something(SYS_fstat64, vers, fd, buf);
}

int __fxstat(int vers, int fd, struct stat* buf)
{
	struct stat64 tmp;
	int ret = __fxstat64(vers, fd, &tmp);
	if (0 == ret && buf) {
		return copy_to_stat(&tmp, buf);
	}
	return ret;
}

int gettimeofday(struct timeval* tp, struct timezone* tzp)
{
	void *ptr = prep_syscall();
	struct timeval *tp2 = NULL;
	struct timezone *tzp2 = NULL;
	long ret;

	if (tp) {
		tp2 = ptr;
		ptr += sizeof(struct timeval);
	}
	if (tzp) {
		tzp2 = ptr;
		ptr += sizeof(struct timezone);
	}
	if (!start_commit_buffered_syscall(SYS_gettimeofday, ptr, NO_DESCHED)) {
		return syscall(SYS_gettimeofday, tp, tzp);
	}
	ret = untraced_syscall2(SYS_gettimeofday, tp2, tzp2);
	if (tp) {
		memcpy(tp, tp2, sizeof(struct timeval));
	}
	if (tzp) {
		memcpy(tzp, tzp2, sizeof(struct timezone));
	}
	return commit_syscall(SYS_gettimeofday, ptr, ret, NO_DESCHED);
}

int __lxstat64(int vers, const char* path, struct stat64* buf)
{
	return stat_something(SYS_lstat64, vers, (uintptr_t)path, buf);
}

int __lxstat(int vers, const char* path, struct stat* buf)
{
	struct stat64 tmp;
	int ret = __lxstat64(vers, path, &tmp);
	if (0 == ret && buf) {
		return copy_to_stat(&tmp, buf);
	}
	return ret;
}

int madvise(void* addr, size_t length, int advice)
{
	void* ptr = prep_syscall();
	long ret;

	if (!start_commit_buffered_syscall(SYS_madvise, ptr, NO_DESCHED)) {
		return syscall(SYS_madvise, addr, length, advice);
	}
	ret = untraced_syscall3(SYS_madvise, addr, length, advice);
	return commit_syscall(SYS_madvise, ptr, ret, NO_DESCHED);
}

int open(const char* pathname, int flags, ...)
{
	/* NB: not arming the desched event is technically correct,
	 * since open() can't deadlock if it blocks.  However, not
	 * allowing descheds here may cause performance issues if the
	 * open does block for a while.  Err on the side of simplicity
	 * until we have perf data. */
	void* ptr;
	int mode = 0;
	long ret;

	if (is_blacklisted_filename(pathname)) {
		/* Would be nice to log_info() here, but that would
		 * flush the syscallbuf ...  This special bail-out
		 * case is deterministic, so no need to save any
		 * breadcrumbs in the syscallbuf. */
		errno = ENOENT;
		return -1;
	}

	ptr = prep_syscall();

	if (O_CREAT & flags) {
		va_list mode_arg;
		va_start(mode_arg, flags);
		mode = va_arg(mode_arg, int);
		va_end(mode_arg);
	}
	if (!start_commit_buffered_syscall(SYS_open, ptr, NO_DESCHED)) {
		return syscall(SYS_open, pathname, flags, mode);
	}

	ret = untraced_syscall3(SYS_open, pathname, flags, mode);
	return commit_syscall(SYS_open, ptr, ret, NO_DESCHED);
}

int open64(const char* pathname, int flags, ...)
{
	int mode = 0;
	if (O_CREAT & flags) {
		va_list mode_arg;
		va_start(mode_arg, flags);
		mode = va_arg(mode_arg, int);
		va_end(mode_arg);
	}
	return open(pathname, flags | O_LARGEFILE, mode);
}

ssize_t read(int fd, void* buf, size_t count)
{
	void* ptr = prep_syscall();
	void* buf2 = NULL;
	long ret;

	if (buf && count > 0) {
		buf2 = ptr;
		ptr += count;
	}
	if (!start_commit_buffered_syscall(SYS_read, ptr,
					   WILL_ARM_DESCHED_EVENT)) {
		return syscall(SYS_read, fd, buf, count);
	}

	arm_desched_event();
	ret = untraced_syscall3(SYS_read, fd, buf2, count);
	disarm_desched_event();

	if (buf2 && ret > 0) {
		memcpy(buf, buf2, ret);
	}
	return commit_syscall(SYS_read, ptr, ret, DISARMED_DESCHED_EVENT);
}

ssize_t readlink(const char* path, char* buf, size_t bufsiz)
{
	void* ptr = prep_syscall();
	char* buf2 = NULL;
	long ret;

	if (buf && bufsiz > 0) {
		buf2 = ptr;
		ptr += bufsiz;
	}
	if (!start_commit_buffered_syscall(SYS_readlink, ptr, NO_DESCHED)) {
		return syscall(SYS_readlink, path, buf, bufsiz);
	}

	ret = untraced_syscall3(SYS_readlink, path, buf2, bufsiz);
	if (buf2 && ret > 0) {
		memcpy(buf, buf2, ret);
	}
	return commit_syscall(SYS_readlink, ptr, ret, NO_DESCHED);
}

ssize_t recv(int sockfd, void* buf, size_t len, int flags)
{
	void* ptr = prep_syscall();
	void* buf2 = NULL;
	long ret;

	if (buf && len > 0) {
		buf2 = ptr;
		ptr += len;
	}
	if (!start_commit_buffered_syscall(SYS_socketcall, ptr,
					   WILL_ARM_DESCHED_EVENT)) {
		return traced_socketcall4(SYS_RECV, sockfd, buf, len, flags);
	}

	arm_desched_event();
	ret = untraced_socketcall4(SYS_RECV, sockfd, buf2, len, flags);
	disarm_desched_event();

	if (buf2 && ret > 0) {
		memcpy(buf, buf2, ret);
	}
	return commit_syscall(SYS_socketcall, ptr, ret, DISARMED_DESCHED_EVENT);
}

time_t time(time_t* t)
{
	void* ptr = prep_syscall();
	long ret;

	if (!start_commit_buffered_syscall(SYS_time, ptr, NO_DESCHED)) {
		return syscall(SYS_time, t);
	}
	ret = untraced_syscall1(SYS_time, NULL);
	if (t) {
		/* No error is possible here. */
		*t = ret;
	}
	return commit_syscall(SYS_time, ptr, ret, NO_DESCHED);
}

ssize_t write(int fd, const void* buf, size_t count)
{
	void* ptr = prep_syscall();
	long ret;

	if (!start_commit_buffered_syscall(SYS_write, ptr,
					   WILL_ARM_DESCHED_EVENT)) {
		return syscall(SYS_write, fd, buf, count);
	}

	arm_desched_event();
	ret = untraced_syscall3(SYS_write, fd, buf, count);
	disarm_desched_event();

	return commit_syscall(SYS_write, ptr, ret, DISARMED_DESCHED_EVENT);
}

int __xstat64(int vers, const char* path, struct stat64* buf)
{
	return stat_something(SYS_stat64, vers, (uintptr_t)path, buf);
}

int __xstat(int vers, const char* path, struct stat* buf)
{
	struct stat64 tmp;
	int ret = __xstat64(vers, path, &tmp);
	if (0 == ret && buf) {
		return copy_to_stat(&tmp, buf);
	}
	return ret;
}
