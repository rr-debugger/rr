/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

//#define DEBUGTAG "rrpreload"

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
 * o No rr headers (other than seccomp-bpf.h and rr.h) may be included
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
#include "rr/rr.h"
#include "seccomp-bpf.h"

#ifdef memcpy
# undef memcpy
#endif
#define memcpy you_must_use_local_memcpy

#ifdef syscall
# undef syscall
#endif
#define syscall you_must_use_traced_syscall

/**
 * Copy |_rhs| to |_lhs|.  If the copy overflows, set errno to
 * EOVERFLOW and return -1.
 *
 * WARNING: this macro affects control flow, use with great care.
 */
#define COPY_CHECK_OVERFLOW(_lhs, _rhs)					\
	do {								\
		_lhs = _rhs;						\
		if (sizeof(_lhs) != sizeof(_rhs) && (_lhs) != (_rhs)) {	\
			errno = EOVERFLOW;				\
			return -1;					\
		}							\
	} while(0)

/**
 * Tracks per-task state that may need to be cleaned up on task exit.
 * 
 * Cleanup must be done in the tracee because the rr process doesn't
 * know that threads are going to exit until it's too late to clean up
 * their state.
 */
struct task_cleanup_data {
	void* scratch_ptr;
	size_t num_scratch_bytes;
	void* syscallbuf_ptr;
	size_t num_syscallbuf_bytes;
	int desched_counter_fd;
};

/* Nonzero when syscall buffering is enabled. */
static int buffer_enabled;

/* Key for per-thread |task_cleanup_data| object. */
static pthread_key_t task_cleanup_data_key;

/* During thread/process initialization, we have to call into libdl in
 * order to resolve the pthread_create symbol.  But libdl can and does
 * call libc functions that we wrap here.  The initialization code
 * obviously doesn't nest, so we use this helper variable as a
 * re-entry guard.  It's nonzero after |ensure_thread_init()| is
 * called the first time. */
static __thread int called_ensure_thread_init;
/* When buffering is enabled, this points at the thread's mapped
 * buffer segment.  At the start of the segment is an object of type
 * |struct syscallbuf_hdr|, so |buffer| is also a pointer to the
 * buffer header.*/
static __thread byte* buffer;
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
 * Thus enter the "desched counter".  It's a perf_event for the "sw t
 * switches" event (which, more precisely, is "sw deschedule"; it
 * counts schedule-out, not schedule-in).  We program the counter to
 * deliver a signal to this task when there's new counter data
 * available.  And we set up the "sample period", how many descheds
 * are triggered before the signal is delivered, to be "1".  This
 * means that when the counter is armed, the next desched (i.e., the
 * next time the desched counter is bumped up) of this task will
 * deliver the signal to it.  And signal delivery always generates a
 * ptrace trap, so rr can deduce that this task was descheduled and
 * schedule another.
 *
 * The description above is sort of an idealized view; there are
 * numerous implementation details that are documented in
 * handle_signal.c, where they're dealt with. */
static __thread int desched_counter_fd;

/* Points at the libc/pthread pthread_create().  We wrap
 * pthread_create, so need to retain this pointer to call out to the
 * libc version. */
static int (*real_pthread_create)(pthread_t* thread,
				  const pthread_attr_t* attr,
				  void* (*start_routine) (void*), void* arg);

/**
 * Return a pointer to the buffer header, which happens to occupy the
 * initial bytes in the mapped region.
 */
static struct syscallbuf_hdr* buffer_hdr(void)
{
	return (struct syscallbuf_hdr*)buffer;
}

/**
 * Return a pointer to the byte just after the last valid syscall record in
 * the buffer.
 */
static byte* buffer_last(void)
{
	return (byte*)next_record(buffer_hdr());
}

/**
 * Return a pointer to the byte just after the very end of the mapped
 * region.
 */
static byte* buffer_end(void)
{
	return buffer + SYSCALLBUF_BUFFER_SIZE;
}

/**
 * Same as libc memcpy(), but usable within syscallbuf transaction
 * critical sections.
 */
static void* local_memcpy(void* dest, const void* source, size_t n)
{
	char* dst = dest;
	const char* src = source;

	while (n--) *dst++ = *src++;

	return dest;
}

/* The following are wrappers for the syscalls invoked by this library
 * itself.  These syscalls will generate ptrace traps. */

long _raw_traced_syscall(int syscallno, long a0, long a1, long a2,
			 long a3, long a4, long a5);
__asm__(".text\n\t"
	".globl _raw_traced_syscall\n\t"
	".type _raw_traced_syscall, @function\n\t"
	"_raw_traced_syscall:\n\t" /* syscallno = 4(%esp) */
	".cfi_startproc\n\t"

	"pushl %ebx\n\t"	/* syscallno = 8(%esp) */
	".cfi_adjust_cfa_offset 4\n\t"
	".cfi_rel_offset %ebx, 0\n\t"
	"pushl %esi\n\t"	/* syscallno = 12(%esp) */
	".cfi_adjust_cfa_offset 4\n\t"
	".cfi_rel_offset %esi, 0\n\t"
	"pushl %edi\n\t"	/* syscallno = 16(%esp) */
	".cfi_adjust_cfa_offset 4\n\t"
	".cfi_rel_offset %edi, 0\n\t"
	"pushl %ebp\n\t"	/* syscallno = 20(%esp) */
	".cfi_adjust_cfa_offset 4\n\t"
	".cfi_rel_offset %ebp, 0\n\t"

	"movl 20(%esp), %eax\n\t" /* %eax = syscallno */
	"movl 24(%esp), %ebx\n\t" /* %ebx = a0 */
	"movl 28(%esp), %ecx\n\t" /* %ecx = a1 */
	"movl 32(%esp), %edx\n\t" /* %edx = a2 */
	"movl 36(%esp), %esi\n\t" /* %esi = a3 */
	"movl 40(%esp), %edi\n\t" /* %edi = a4 */
	"movl 44(%esp), %ebp\n\t" /* %ebp = a5 */

	"int $0x80\n\t"		/* syscall() */
	/* When the tracee is in the traced syscall, its $ip will be
	 * the value of this label.  We need to be able to recognize
	 * when the tracees are in traced syscalls. */
	".L_traced_syscall_entry_point_ip:\n\t"

	"popl %ebp\n\t"
	".cfi_adjust_cfa_offset -4\n\t"
	".cfi_restore %ebp\n\t"
	"popl %edi\n\t"
	".cfi_adjust_cfa_offset -4\n\t"
	".cfi_restore %edi\n\t"
	"popl %esi\n\t"
	".cfi_adjust_cfa_offset -4\n\t"
	".cfi_restore %esi\n\t"
	"popl %ebx\n\t"
	".cfi_adjust_cfa_offset -4\n\t"
	".cfi_restore %ebx\n\t"
	"ret\n\t"
	".cfi_endproc\n\t"
	".size _raw_traced_syscall, .-_raw_traced_syscall\n\t");

static int update_errno_ret(long ret)
{
	/* EHWPOISON is the last known errno as of linux 3.9.5. */
	if (0 > ret && ret >= -EHWPOISON) {
		errno = -ret;
		ret = -1;
	}
	return ret;
}

static int traced_syscall(int syscallno, long a0, long a1, long a2,
			  long a3, long a4, long a5)
{
	long ret = _raw_traced_syscall(syscallno, a0, a1, a2, a3, a4, a5);
	return update_errno_ret(ret);
}
#define traced_syscall6(no, a0, a1, a2, a3, a4, a5)			\
	traced_syscall(no, (uintptr_t)a0, (uintptr_t)a1, (uintptr_t)a2, (uintptr_t)a3, (uintptr_t)a4, (uintptr_t)a5)
#define traced_syscall5(no, a0, a1, a2, a3, a4)	\
	traced_syscall6(no, a0, a1, a2, a3, a4, 0)
#define traced_syscall4(no, a0, a1, a2, a3)	\
	traced_syscall5(no, a0, a1, a2, a3, 0)
#define traced_syscall3(no, a0, a1, a2)		\
	traced_syscall4(no, a0, a1, a2, 0)
#define traced_syscall2(no, a0, a1)		\
	traced_syscall3(no, a0, a1, 0)
#define traced_syscall1(no, a0)			\
	traced_syscall2(no, a0, 0)
#define traced_syscall0(no)			\
	traced_syscall1(no, 0)

/**
 * "Raw" traced syscalls return the raw kernel return value, and don't
 * transform it to -1/errno per POSIX semantics.
 */
#define raw_traced_syscall6(no, a0, a1, a2, a3, a4, a5)			\
	_raw_traced_syscall(no, (uintptr_t)a0, (uintptr_t)a1, (uintptr_t)a2, (uintptr_t)a3, (uintptr_t)a4, (uintptr_t)a5)
#define raw_traced_syscall5(no, a0, a1, a2, a3, a4)	\
	raw_traced_syscall6(no, a0, a1, a2, a3, a4, 0)
#define raw_traced_syscall4(no, a0, a1, a2, a3)	\
	raw_traced_syscall5(no, a0, a1, a2, a3, 0)
#define raw_traced_syscall3(no, a0, a1, a2)	\
	raw_traced_syscall4(no, a0, a1, a2, 0)
#define raw_traced_syscall2(no, a0, a1)		\
	raw_traced_syscall3(no, a0, a1, 0)
#define raw_traced_syscall1(no, a0)		\
	raw_traced_syscall2(no, a0, 0)
#define raw_traced_syscall0(no)			\
	raw_traced_syscall1(no, 0)

static void* get_traced_syscall_entry_point(void)
{
    void *ret;
    __asm__ __volatile__(
	    "call _get_traced_syscall_entry_point__pic_helper\n\t"
	    "_get_traced_syscall_entry_point__pic_helper: pop %0\n\t"
	    "addl $(.L_traced_syscall_entry_point_ip - _get_traced_syscall_entry_point__pic_helper),%0"
	    : "=a"(ret));
    return ret;
}

static int traced_close(int fd)
{
	return traced_syscall1(SYS_close, fd);
}

static int traced_fcntl(int fd, int cmd, ...)
{
	va_list ap;
	void *arg;

	va_start(ap, cmd);
	arg = va_arg(ap, void*);
	va_end(ap);

	return traced_syscall3(SYS_fcntl64, fd, cmd, arg);
}

static pid_t traced_getpid(void)
{
	return traced_syscall0(SYS_getpid);
}

static pid_t traced_gettid(void)
{
	return traced_syscall0(SYS_gettid);
}

static int traced_munmap(void* addr, size_t length)
{
	return traced_syscall2(SYS_munmap, addr, length);
}

static int traced_perf_event_open(struct perf_event_attr *attr,
				  pid_t pid, int cpu, int group_fd,
				  unsigned long flags)
{
    return traced_syscall5(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static int traced_prctl(int option, unsigned long arg2, unsigned long arg3,
		     unsigned long arg4, unsigned long arg5)
{
	return traced_syscall5(SYS_prctl, option, arg2, arg3, arg4, arg5);
}

static int traced_raise(int sig)
{
	return traced_syscall2(SYS_kill, traced_getpid(), sig);
}

static int traced_sigprocmask(int how, const sigset_t* set, sigset_t* oldset)
{
	/* Warning: expecting this to only change the mask of the
	 * current task is a linux-ism; POSIX leaves the behavior
	 * undefined. */
	return traced_syscall3(SYS_rt_sigprocmask, how, set, oldset);
}

static ssize_t traced_write(int fd, const void* buf, size_t count)
{
	return traced_syscall3(SYS_write, fd, buf, count);
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
			logmsg("%s:%d: Assertion `" #cond "' failed.\n", \
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

#ifdef DEBUGTAG
# define debug(msg, ...)						\
	logmsg("[INFO] (%s:%d) " msg "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
# define debug(msg, ...) ((void)0)
#endif

/**
 * Mask out all signals in preparation for a critical section.
 * Previous mask saved to |saved_mask|, which should be passed to
 * |exit_signal_critical_section()|.
 */
static void enter_signal_critical_section(sigset_t* saved_mask)
{
	sigset_t mask;
	sigfillset(&mask);
	traced_sigprocmask(SIG_BLOCK, &mask, saved_mask);
}

/**
 * Restore |saved_mask|, after exiting critical section.
 */
static void exit_signal_critical_section(const sigset_t* saved_mask)
{
	traced_sigprocmask(SIG_SETMASK, saved_mask, NULL);
}

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

static void* get_untraced_syscall_entry_point(void)
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
 * Save the syscall params to this struct so that we can pass around a
 * pointer to it and avoid pushing/popping all this data for calls to
 * subsequent handlers.
 */
struct syscall_info {
    long no;
    long args[6];
};

/**
 * Call this hook from |__kernel_vsyscall()|, to buffer syscalls that
 * we otherwise couldn't wrap through LD_PRELOAD helpers.  Return the
 * *RAW* kernel return value, not the -1/errno mandated by POSIX.
 *
 * Remember, this function runs *below* the level of libc.  libc can't
 * know that its call to |__kernel_vsyscall()| has been re-routed to
 * us.
 */
static long vsyscall_hook(const struct syscall_info* call);

/**
 * |__kernel_vsyscall()| is /actually/ patched to jump here.  This
 * trampoline then prepares a "real" call to |vsyscall_hook()|.
 */
__asm__(".text\n\t"
	".globl _vsyscall_hook_trampoline\n\t"
	".type _vsyscall_hook_trampoline, @function\n\t"
	"_vsyscall_hook_trampoline:\n\t"
	".cfi_startproc\n\t"

	/* The monkeypatch pushed $eax on the stack, but there's no
	 * CFI info for it.  Fix up the CFA offset here to account for
	 * the monkeypatch code. */
        ".cfi_adjust_cfa_offset 4\n\t"
        ".cfi_rel_offset %eax, 0\n\t"

        /* Pull $eax back off the stack.  Now our syscall-arg
         * registers are restored to their state on entry to
         * __kernel_vsyscall(). */
        "popl %eax\n\t"
	".cfi_adjust_cfa_offset -4\n\t"
	".cfi_restore %eax\n\t"

        /* Build a |struct syscall_info| by pushing all the syscall
         * args and the number onto the stack. */
                                /* struct syscall_info info; */
        "pushl %ebp\n\t"        /* info.args[5] = $ebp; */
	".cfi_adjust_cfa_offset 4\n\t"
	".cfi_rel_offset %ebp, 0\n\t"
        "pushl %edi\n\t"        /* info.args[4] = $edi; */
	".cfi_adjust_cfa_offset 4\n\t"
	".cfi_rel_offset %edi, 0\n\t"
        "pushl %esi\n\t"        /* info.args[3] = $esi; */
	".cfi_adjust_cfa_offset 4\n\t"
	".cfi_rel_offset %esi, 0\n\t"
        "pushl %edx\n\t"        /* info.args[2] = $edx; */
	".cfi_adjust_cfa_offset 4\n\t"
	".cfi_rel_offset %edx, 0\n\t"
        "pushl %ecx\n\t"        /* info.args[1] = $ecx; */
	".cfi_adjust_cfa_offset 4\n\t"
	".cfi_rel_offset %ecx, 0\n\t"
        "pushl %ebx\n\t"        /* info.args[0] = $ebx; */
	".cfi_adjust_cfa_offset 4\n\t"
	".cfi_rel_offset %ebx, 0\n\t"
        "pushl %eax\n\t"        /* info.no = $eax; */
	".cfi_adjust_cfa_offset 4\n\t"

        /* $esp points at &info.  Push that pointer on the stack as
         * our arg for syscall_hook(). */
        "movl %esp, %ecx\n\t"
        "pushl %ecx\n\t"
	".cfi_adjust_cfa_offset 4\n\t"

        "movl $vsyscall_hook, %eax\n\t"
        "call *%eax\n\t"        /* $eax = vsyscall_hook(&info); */

        /* $eax is now the syscall return value.  Erase the |&info|
         * arg and |info.no| from the stack so that we can restore the
         * other registers we saved. */
        "addl $8, %esp\n\t"
	".cfi_adjust_cfa_offset -8\n\t"

        /* Contract of __kernel_vsyscall() is that even callee-save
         * registers aren't touched, so we restore everything here. */
        "popl %ebx\n\t"
	".cfi_adjust_cfa_offset -4\n\t"
	".cfi_restore %ebx\n\t"
        "popl %ecx\n\t"
	".cfi_adjust_cfa_offset -4\n\t"
	".cfi_restore %ecx\n\t"
        "popl %edx\n\t"
	".cfi_adjust_cfa_offset -4\n\t"
	".cfi_restore %edx\n\t"
        "popl %esi\n\t"
	".cfi_adjust_cfa_offset -4\n\t"
	".cfi_restore %esi\n\t"
        "popl %edi\n\t"
	".cfi_adjust_cfa_offset -4\n\t"
	".cfi_restore %edi\n\t"
        "popl %ebp\n\t"
	".cfi_adjust_cfa_offset -4\n\t"
	".cfi_restore %ebp\n\t"

        /* Return to the caller of *|__kernel_vsyscall()|*, because
         * the monkeypatch jumped to us. */
        "ret\n\t"
    	".cfi_endproc\n\t"
        ".size _vsyscall_hook_trampoline, .-_vsyscall_hook_trampoline\n\t");

static void* get_vsyscall_hook_trampoline(void)
{
    void *ret;
    __asm__ __volatile__(
	    "call .L_get_vsyscall_hook_trampoline__pic_helper\n\t"
	    ".L_get_vsyscall_hook_trampoline__pic_helper: pop %0\n\t"
	    "addl $(_vsyscall_hook_trampoline - .L_get_vsyscall_hook_trampoline__pic_helper),%0"
	    : "=a"(ret));
    return ret;
}

/**
 * Do what's necessary to set up buffers for the caller.
 * |untraced_syscall_ip| lets rr know where our untraced syscalls will
 * originate from.  |addr| is the address of the control socket the
 * child expects to connect to.  |msg| is a pre-prepared IPC that can
 * be used to share fds; |fdptr| is a pointer to the control-message
 * data buffer where the fd number being shared will be stored.
 * |args_vec| provides the tracer with preallocated space to make
 * socketcall syscalls.
 *
 * Pointers to the scratch buffer and syscallbuf, if enabled, and
 * their sizes are returned through the outparams.
 *
 * This is a "magic" syscall implemented by rr.
 */
static void rrcall_init_buffers(struct rrcall_init_buffers_params* args)
{
	sigset_t mask;
	enter_signal_critical_section(&mask);
	traced_syscall1(SYS_rrcall_init_buffers, args);
	exit_signal_critical_section(&mask);
}

/**
 * Monkeypatch |__kernel_vsyscall()| to jump into
 * |vdso_hook_trampoline|.
 */
static void rrcall_monkeypatch_vdso(void* vdso_hook_trampoline)
{
	sigset_t mask;
	enter_signal_critical_section(&mask);
	traced_syscall1(SYS_rrcall_monkeypatch_vdso, vdso_hook_trampoline);
	exit_signal_critical_section(&mask);
}

/**
 * This installs the actual filter which examines the callsite and
 * determines whether it will be ptraced or handled by the
 * intercepting library
 */
static void install_syscall_filter(void)
{
	void* untraced_syscall_start = get_untraced_syscall_entry_point();
	struct sock_filter filter[] = {
		/* Allow all system calls from our protected_call
		 * callsite */
		ALLOW_SYSCALLS_FROM_CALLSITE((uintptr_t)untraced_syscall_start),
		/* All the rest are handled in rr */
		TRACE_PROCESS,
	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};

	debug("Initializing syscall buffer: protected_call_start = %p",
	      untraced_syscall_start);

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
 * Unmap and close per-thread resources.  Runs at thread exit.
 */
static void clean_up_task(void* data)
{
	struct task_cleanup_data* cleanup = data;

	traced_munmap(cleanup->scratch_ptr, cleanup->num_scratch_bytes);
	if (cleanup->syscallbuf_ptr) {
		traced_munmap(cleanup->syscallbuf_ptr,
			      cleanup->num_syscallbuf_bytes);
		traced_close(cleanup->desched_counter_fd);
		buffer = NULL;
	}
}

/**
 * Return a counter that generates a signal targeted at this task
 * every time the task is descheduled |nr_descheds| times.
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
	if (traced_fcntl(fd, F_SETSIG, SYSCALLBUF_DESCHED_SIGNAL)) {
		fatal("Failed to fcntl(SETSIG, %d) the desched counter",
		      SYSCALLBUF_DESCHED_SIGNAL);
	}

	return fd;
}

static void set_up_buffer(void)
{
	struct task_cleanup_data* cleanup = malloc(sizeof(*cleanup));
	struct sockaddr_un addr;
	struct msghdr msg;
	struct iovec data;
	int msgbuf;
	struct cmsghdr* cmsg;
	int* msg_fdptr;
	int* cmsg_fdptr;
	char cmsgbuf[CMSG_SPACE(sizeof(*cmsg_fdptr))];
	struct socketcall_args args_vec;
	struct rrcall_init_buffers_params args;

	assert(!buffer);

	memset(cleanup, 0, sizeof(*cleanup));
	pthread_setspecific(task_cleanup_data_key, cleanup);

	/* NB: we want this setup emulated during replay. */
	if (buffer_enabled) {
		cleanup->desched_counter_fd = desched_counter_fd =
					      open_desched_event_counter(1);
	}

	/* Prepare arguments for rrcall.  We do this in the tracee
	 * just to avoid some hairy IPC to set up the arguments
	 * remotely from the tracer; this isn't strictly
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

	args.syscallbuf_enabled = buffer_enabled;
	args.traced_syscall_ip = get_traced_syscall_entry_point();
	args.untraced_syscall_ip = get_untraced_syscall_entry_point();
	args.sockaddr = &addr;
	args.msg = &msg;
	args.fdptr = cmsg_fdptr;
	args.args_vec = &args_vec;

	/* Trap to rr: let the magic begin!  We've prepared the buffer
	 * so that it's immediately ready to be sendmsg()'d to rr to
	 * share the desched counter to it (under rr's control).  rr
	 * can further use the buffer to share more fd's to us. */
	rrcall_init_buffers(&args);

	/* rr initializes the buffer header. */
	buffer = cleanup->syscallbuf_ptr = args.syscallbuf_ptr;
	cleanup->scratch_ptr = args.scratch_ptr;
	cleanup->num_scratch_bytes = args.num_scratch_bytes;
	cleanup->syscallbuf_ptr = args.syscallbuf_ptr;
	cleanup->num_syscallbuf_bytes = args.num_syscallbuf_bytes;
}

/**
 * After a fork(), the new child will still share the buffer mapping
 * with its parent.  That's obviously very bad.  Pretend that we don't
 * know about the old buffer, so that the next time a buffered syscall
 * is hit, we map a new buffer.
 */
static void drop_buffer(void)
{
	buffer = NULL;
	called_ensure_thread_init = 0;
	pthread_setspecific(task_cleanup_data_key, NULL);
}

/**
 * Initialize process-global buffering state, if enabled.
 */
static pthread_once_t init_process_once = PTHREAD_ONCE_INIT;
static void init_process(void)
{
	int ret;

	buffer_enabled = !!getenv(SYSCALLBUF_ENABLED_ENV_VAR);
	if (buffer_enabled) {
		install_syscall_filter();
		pthread_atfork(NULL, NULL, drop_buffer);
		rrcall_monkeypatch_vdso(get_vsyscall_hook_trampoline());
	} else {
		debug("Syscall buffering is disabled");
	}

	if ((ret = pthread_key_create(&task_cleanup_data_key,
				      clean_up_task))) {
		fatal("pthread_key_create() failed with code %d", ret);
	}

	real_pthread_create = dlsym(RTLD_NEXT, "pthread_create");
}

/**
 * Initialize thread-local buffering state, if enabled.
 */
enum { NO_SIGNAL_SAFETY, ASYNC_SIGNAL_SAFE };
static void ensure_thread_init(int signal_safety)
{
	if (called_ensure_thread_init) {
		return;
	}
	if (ASYNC_SIGNAL_SAFE == signal_safety) {
		/* Our initialization can end up calling malloc() and
		 * other potentially non-async-signal-safe functions,
		 * so we can't init from a context in which
		 * async-signal-safety needs to be preserved. */
		debug("(refusing to init from async-signal-safe context)");
		return;
	}
	called_ensure_thread_init = 1;
	pthread_once(&init_process_once, init_process);
	assert(!pthread_getspecific(task_cleanup_data_key));
	set_up_buffer();
}

static void __attribute__((constructor))
init_process_static(void)
{
	ensure_thread_init(NO_SIGNAL_SAFETY);
}

/**
 * In a thread newly created by |pthread_create()|, first initialize
 * thread-local internal rr data, then trampoline into the user's
 * thread function.
 */
struct thread_func_data {
	void* (*start_routine) (void*);
	void* arg;
};
static void* thread_trampoline(void* arg)
{
	struct thread_func_data* data = arg;
	void* ret;

	ensure_thread_init(NO_SIGNAL_SAFETY);

	ret = data->start_routine(data->arg);

	free(data);
	return ret;
}

/**
 * Interpose |pthread_create()| so that we can use a custom trampoline
 * function (see above) that initializes rr thread-local data for new
 * threads.
 *
 * This is a wrapper of |pthread_create()|, but not like the ones
 * below: we don't wrap |pthread_create()| in order to buffer its
 * syscalls, rather in order to initialize rr thread data.
 */
int pthread_create(pthread_t* thread, const pthread_attr_t* attr,
		   void* (*start_routine) (void*), void* arg)
{
	struct thread_func_data* data;

	ensure_thread_init(NO_SIGNAL_SAFETY);

	data = malloc(sizeof(*data));
	data->start_routine = start_routine;
	data->arg = arg;
	return real_pthread_create(thread, attr, thread_trampoline, data);
}

/**
 * Wrappers start here.
 *
 * !!! NBB !!!: from here on, all code that executes within the
 * critical sections of transactions *MUST KEEP $ip IN THE SYSCALLBUF
 * CODE*.  That means no calls into libc, even for innocent-looking
 * functions like |memcpy()|.
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
 *   // required internal bookkeeping data.  If the wrapper is for
 *   // an async-signal-safe libc function, pass ASYNC_SIGNAL_SAFE.
 *   // Otherwise pass NO_SIGNAL_SAFETY.
 *   void* ptr = prep_syscall(ASYNC_SIGNAL_SAFETY);
 *
 *   // If the syscall requires recording any extra data, reserve
 *   // space for it too.
 *   ptr += sizeof(extra_syscall_data);
 *
 *   // If there's not enough space, bail.  Since this syscall may
 *   // block, arm/disarm the desched notification.
 *   if (!start_commit_buffered_syscall(SYS_foo, ptr, MAY_BLOCK)) {
 *       goto fallback_trace;
 *   }
 *
 *   untraced_syscall(...);
 *
 *   // Store the extra_syscall_data that space was reserved for
 *   // above.
 *
 *   // Update the buffer.
 *   return commit_syscall(...);
 *
 * fallback_trace:
 *   return syscall(...);  // traced
 */

static void* prep_syscall(int signal_safety)
{
	ensure_thread_init(signal_safety);
	if (!buffer) {
		return NULL;
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

static void arm_desched_event(void)
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

static void disarm_desched_event(void)
{
	/* See above. */
	if (untraced_syscall3(SYS_ioctl, desched_counter_fd,
			      PERF_EVENT_IOC_DISABLE, 0)) {
		fatal("Failed to DISABLE counter %d", desched_counter_fd);
	}
}

/**
 * Return 1 if it's ok to proceed with buffering this system call.
 * Return 0 if we should trace the system call.
 * This must be checked before proceeding with the buffered system call.
 */
/* (Negative numbers so as to not be valid syscall numbers, in case
 * the |int| arguments below are passed in the wrong order.) */
enum { MAY_BLOCK = -1, WONT_BLOCK = -2 };
static int start_commit_buffered_syscall(int syscallno, void* record_end,
					 int blockness)
{
	void* record_start;
	void* stored_end;
	struct syscallbuf_record* rec;

	if (!buffer) {
		return 0;
	}
	record_start = buffer_last();
	stored_end =
		record_start + stored_record_size(record_end - record_start);
	rec = record_start;

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
	rec->desched = MAY_BLOCK == blockness;
	rec->size = record_end - record_start;
	if (rec->desched) {
		/* NB: the ordering of the next two statements is
		 * important.
		 *
		 * We set this flag to notify rr that it should pay
		 * attention to desched signals pending for this task.
		 * We have to set it *before* we arm the notification
		 * because we can't set the flag atomically with
		 * arming the event (too bad there's no ioctl() for
		 * querying the event enabled-ness state).  That's
		 * important because if the notification is armed,
		 * then rr must be confident that when it disarms the
		 * event, the tracee is at an execution point that
		 * *must not* need the desched event.
		 *
		 * If we were to set the flag non-atomically after the
		 * event was armed, then if a desched signal was
		 * delivered right at the instruction that set the
		 * flag, rr wouldn't know that it needed to advance
		 * the tracee to the untraced syscall entry point.
		 * (And if rr didn't do /that/, then the syscall might
		 * block without rr knowing it, and the recording
		 * session would deadlock.) */
		buffer_hdr()->desched_signal_may_be_relevant = 1;
		arm_desched_event();
	}
	return 1;
}

/**
 * Commit the record for a buffered system call.  record_end can be
 * adjusted downward from what was passed to
 * start_commit_buffered_syscall, if not all of the initially
 * requested space is needed.  The result of this function should be
 * returned directly by the kernel vsyscall hook.
 */
static long commit_raw_syscall(int syscallno, void* record_end, int ret)
{
	void* record_start = buffer_last();
	struct syscallbuf_record* rec = record_start;
	struct syscallbuf_hdr* hdr = buffer_hdr();

	/* NB: the ordering of this statement with the
	 * |disarm_desched_event()| call below is important.
	 *
	 * We clear this flag to notify rr that the may-block syscall
	 * has finished, so there's no danger of blocking anymore.
	 * (And thus the desched signal is no longer relevant.)  We
	 * have to clear this *before* disarming the event, because if
	 * rr sees the flag set, it has to PTRACE_SYSCALL this task to
	 * ensure it reaches an execution point where the desched
	 * signal is no longer relevant.  We have to use the ioctl()
	 * that disarms the event as a safe "backstop" that can be hit
	 * by the PTRACE_SYSCALL.
	 *
	 * If we were to clear the flag *after* disarming the event,
	 * and the signal arrived at the instruction that cleared the
	 * flag, and rr issued the PTRACE_SYSCALL, then this tracee
	 * could fly off to any unknown execution point, including an
	 * iloop.  So the recording session could livelock. */
	hdr->desched_signal_may_be_relevant = 0;

	if (rec->syscallno != syscallno) {
		fatal("Record is for %d but trying to commit %d",
		      rec->syscallno, syscallno);
	}

	if (hdr->abort_commit) {
		/* We were descheduled in the middle of a may-block
		 * syscall, and it was recorded as a normal entry/exit
		 * pair.  So don't record the syscall in the buffer or
		 * replay will go haywire. */
		hdr->abort_commit = 0;
	} else {
		rec->ret = ret;
		hdr->num_rec_bytes += stored_record_size(rec->size);
	}

	if (rec->desched) {
		disarm_desched_event();
	}
	/* NBB: for may-block syscalls that are descheduled, the
	 * tracer uses the previous ioctl() as a stable point to reset
	 * the record counter.  Therefore nothing from here on in the
	 * current txn must touch the record counter (at least, must
	 * not assume it's unchanged). */

	buffer_hdr()->locked = 0;

	return ret;
}

/**
 *  Soon-to-be obsoleted version of |commit_raw_syscall()| for libc
 *  wrappers.
 */
static int commit_syscall(int syscallno, void* record_end, int ret)
{
	return update_errno_ret(commit_raw_syscall(syscallno, record_end, ret));
}

/**
 * Make the traced socketcall |call| with the given args.
 *
 * NB: this helper *DOES* update errno and massage the return value.
 */
static int traced_socketcall(int call,
			     long a0, long a1, long a2, long a3, long a4)
{
	unsigned long args[] = { a0, a1, a2, a3, a4 };
	return traced_syscall2(SYS_socketcall, call, args);
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
static long untraced_socketcall(int call,
				long a0, long a1, long a2, long a3, long a4)
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

static int fcntl0(int fd, int cmd)
{
	/* No zero-arg fcntl's are known to be may-block. */
	void* ptr = prep_syscall(ASYNC_SIGNAL_SAFE);
	long ret;

	if (!start_commit_buffered_syscall(SYS_fcntl64, ptr, WONT_BLOCK)) {
		return traced_syscall2(SYS_fcntl64, fd, cmd);
 	}
	ret = untraced_syscall2(SYS_fcntl64, fd, cmd);
	return commit_syscall(SYS_fcntl64, ptr, ret);
}

static int fcntl1(int fd, int cmd, int arg)
{
	/* No one-int-arg fcntl's are known to be may-block. */
	void* ptr = prep_syscall(ASYNC_SIGNAL_SAFE);
	long ret;

	if (!start_commit_buffered_syscall(SYS_fcntl64, ptr, WONT_BLOCK)) {
		return traced_syscall3(SYS_fcntl64, fd, cmd, arg);
	}
	ret = untraced_syscall3(SYS_fcntl64, fd, cmd, arg);
	return commit_syscall(SYS_fcntl64, ptr, ret);
}

static int fcntl_own_ex(int fd, int cmd, struct f_owner_ex* owner)
{
	/* The OWN_EX fcntl's aren't may-block. */
	void* ptr = prep_syscall(ASYNC_SIGNAL_SAFE);
	struct f_owner_ex* owner2 = NULL;
	long ret;

	if (owner) {
		owner2 = ptr;
		ptr += sizeof(*owner2);
	}
	if (!start_commit_buffered_syscall(SYS_fcntl64, ptr, WONT_BLOCK)) {
		return traced_syscall3(SYS_fcntl64, fd, cmd, owner);
	}
	if (owner2) {
		local_memcpy(owner2, owner, sizeof(*owner2));
	}
	ret = untraced_syscall3(SYS_fcntl64, fd, cmd, owner2);
	if (owner2) {
		local_memcpy(owner, owner2, sizeof(*owner));
	}
	return commit_syscall(SYS_fcntl64, ptr, ret);
}

static int fcntl_flock(int fd, int cmd, struct flock64* lock)
{
	/* Quite unfortunately, the flock ABI uses the l_type field as
	 * an inout param.  To buffer that field, we'd have to copy-in
	 * the value passed by the user, then store the value returned
	 * by the kernel.  But during replay, that would write data to
	 * the syscallbuf without any way to recover the stored
	 * outparam data.  Because of that, we have to always trace
	 * flock operations. */
	return traced_syscall3(SYS_fcntl64, fd, cmd, lock);
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
	case F_SETSIG: {
		va_list varg;
		int arg;

		va_start(varg, cmd);
		arg = va_arg(varg, int);
		va_end(varg);

		return fcntl1(fd, cmd, arg);
	}
	case F_GETOWN_EX:
	case F_SETOWN_EX: {
		va_list varg;
		struct f_owner_ex* owner;

		va_start(varg, cmd);
		owner = va_arg(varg, struct f_owner_ex*);
		va_end(varg);

		return fcntl_own_ex(fd, cmd, owner);
	}
	case F_GETLK:
	case F_SETLK:
	case F_SETLKW: {
		va_list varg;
		int cmd64;
		struct flock* lock;
		struct flock64 lock64;
		int ret;

		switch (cmd) {
		case F_GETLK: cmd64 = F_GETLK64; break;
		case F_SETLK: cmd64 = F_SETLK64; break;
		case F_SETLKW: cmd64 = F_SETLKW64; break;
		}

		va_start(varg, cmd);
		lock = va_arg(varg, struct flock*);
		va_end(varg);

		lock64.l_type = lock->l_type;
		lock64.l_whence = lock->l_whence;
		COPY_CHECK_OVERFLOW(lock64.l_start, lock->l_start);
		COPY_CHECK_OVERFLOW(lock64.l_len, lock->l_len);
		lock64.l_pid = lock->l_pid;

		ret = fcntl_flock(fd, cmd64, &lock64);

		lock->l_type = lock64.l_type;
		lock->l_whence = lock64.l_whence;
		COPY_CHECK_OVERFLOW(lock->l_start, lock64.l_start);
		COPY_CHECK_OVERFLOW(lock->l_len, lock64.l_len);
		lock->l_pid = lock64.l_pid;
		return ret;
	}
	case F_GETLK64:
	case F_SETLK64:
	case F_SETLKW64: {
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

ssize_t recv(int sockfd, void* buf, size_t len, int flags)
{
	void* ptr = prep_syscall(ASYNC_SIGNAL_SAFE);
	void* buf2 = NULL;
	long ret;

	if (buf && len > 0) {
		buf2 = ptr;
		ptr += len;
	}
	if (!start_commit_buffered_syscall(SYS_socketcall, ptr, MAY_BLOCK)) {
		return traced_socketcall4(SYS_RECV, sockfd, buf, len, flags);
	}

	ret = untraced_socketcall4(SYS_RECV, sockfd, buf2, len, flags);

	if (buf2 && ret > 0) {
		local_memcpy(buf, buf2, ret);
	}
	return commit_syscall(SYS_socketcall, ptr, ret);
}

static long sys_access(const struct syscall_info* call)
{
	const int syscallno = SYS_access;
	const char* pathname = (const char*)call->args[0];
	int mode = call->args[1];

	void* ptr = prep_syscall(ASYNC_SIGNAL_SAFE);
	long ret;

	assert(syscallno == call->no);

	if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
		return raw_traced_syscall2(syscallno, pathname, mode);
 	}
	ret = untraced_syscall2(syscallno, pathname, mode);
	return commit_raw_syscall(syscallno, ptr, ret);
}

static long sys_clock_gettime(const struct syscall_info* call)
{
	const int syscallno = SYS_clock_gettime;
	clockid_t clk_id = (clockid_t)call->args[0];
	struct timespec* tp = (struct timespec*)call->args[1];

	void* ptr = prep_syscall(ASYNC_SIGNAL_SAFE);
	struct timespec *tp2 = NULL;
	long ret;

	assert(syscallno == call->no);

	if (tp) {
		tp2 = ptr;
		ptr += sizeof(*tp2);
	}
	if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
		return raw_traced_syscall2(syscallno, clk_id, tp);
 	}
	ret = untraced_syscall2(syscallno, clk_id, tp2);
	if (tp) {
		local_memcpy(tp, tp2, sizeof(*tp));
	}
	return commit_raw_syscall(syscallno, ptr, ret);
}

static long sys_close(const struct syscall_info* call)
{
	const int syscallno = SYS_close;
	int fd = call->args[0];

	void* ptr = prep_syscall(ASYNC_SIGNAL_SAFE);
	long ret;

	if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
		return raw_traced_syscall1(syscallno, fd);
 	}
	ret = untraced_syscall1(syscallno, fd);
	return commit_raw_syscall(syscallno, ptr, ret);
}

static long sys_open(const struct syscall_info* call);
static long sys_creat(const struct syscall_info* call)
{
	int fd = call->args[0];
	mode_t mode = call->args[1];
	/* Thus sayeth the man page:
	 *
	 *   creat() is equivalent to open() with flags equal to
	 *   O_CREAT|O_WRONLY|O_TRUNC. */
	struct syscall_info open_call;
	open_call.no = SYS_open;
	open_call.args[0] = fd;
	open_call.args[1] = O_CREAT | O_TRUNC | O_WRONLY;
	open_call.args[2] = mode;
	return sys_open(&open_call);
}

static long sys_gettimeofday(const struct syscall_info* call)
{
	const int syscallno = SYS_gettimeofday;
	struct timeval* tp = (struct timeval*)call->args[0];
	struct timezone* tzp = (struct timezone*)call->args[1];

	/* XXX it seems odd that clock_gettime() is spec'd to be
	 * async-signal-safe while gettimeofday() isn't, but that's
	 * what the docs say! */
	void *ptr = prep_syscall(NO_SIGNAL_SAFETY);
	struct timeval *tp2 = NULL;
	struct timezone *tzp2 = NULL;
	long ret;

	assert(syscallno == call->no);

	if (tp) {
		tp2 = ptr;
		ptr += sizeof(*tp2);
	}
	if (tzp) {
		tzp2 = ptr;
		ptr += sizeof(*tzp2);
	}
	if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
		return raw_traced_syscall2(syscallno, tp, tzp);
	}
	ret = untraced_syscall2(syscallno, tp2, tzp2);
	if (tp) {
		local_memcpy(tp, tp2, sizeof(*tp));
	}
	if (tzp) {
		local_memcpy(tzp, tzp2, sizeof(*tzp));
	}
	return commit_raw_syscall(syscallno, ptr, ret);
}

static long sys_open(const struct syscall_info* call)
{
	const int syscallno = SYS_open;
	const char* pathname = (const char*)call->args[0];
	int flags = call->args[1];
	mode_t mode = call->args[2];

	/* NB: not arming the desched event is technically correct,
	 * since open() can't deadlock if it blocks.  However, not
	 * allowing descheds here may cause performance issues if the
	 * open does block for a while.  Err on the side of simplicity
	 * until we have perf data. */
	void* ptr;
	long ret;

	/* The strcmp() done here is OK because we're not in the
	 * critical section yet. */
	if (is_blacklisted_filename(pathname)) {
		/* Would be nice to debug() here, but that would flush
		 * the syscallbuf ...  This special bail-out case is
		 * deterministic, so no need to save any breadcrumbs
		 * in the syscallbuf. */
		return -ENOENT;
	}

	ptr = prep_syscall(ASYNC_SIGNAL_SAFE);
	if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
		return raw_traced_syscall3(syscallno, pathname, flags, mode);
	}

	ret = untraced_syscall3(syscallno, pathname, flags, mode);
	return commit_raw_syscall(syscallno, ptr, ret);
}

static long sys_read(const struct syscall_info* call)
{
	const int syscallno = SYS_read;
	int fd = call->args[0];
	void* buf = (void*)call->args[1];
	size_t count = call->args[2];

	void* ptr = prep_syscall(ASYNC_SIGNAL_SAFE);
	void* buf2 = NULL;
	long ret;

	assert(syscallno == call->no);

	if (buf && count > 0) {
		buf2 = ptr;
		ptr += count;
	}
	if (!start_commit_buffered_syscall(syscallno, ptr, MAY_BLOCK)) {
		return raw_traced_syscall3(syscallno, fd, buf, count);
	}

	ret = untraced_syscall3(syscallno, fd, buf2, count);

	if (buf2 && ret > 0) {
		local_memcpy(buf, buf2, ret);
	}
	return commit_raw_syscall(syscallno, ptr, ret);
}

static long sys_readlink(const struct syscall_info* call)
{
	const int syscallno = SYS_readlink;
	const char* path = (const char*)call->args[0];
	char* buf = (char*)call->args[1];
	int bufsiz = call->args[2];

	void* ptr = prep_syscall(ASYNC_SIGNAL_SAFE);
	char* buf2 = NULL;
	long ret;

	assert(syscallno == call->no);

	if (buf && bufsiz > 0) {
		buf2 = ptr;
		ptr += bufsiz;
	}
	if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
		return raw_traced_syscall3(syscallno, path, buf, bufsiz);
	}

	ret = untraced_syscall3(syscallno, path, buf2, bufsiz);
	if (buf2 && ret > 0) {
		local_memcpy(buf, buf2, ret);
	}
	return commit_raw_syscall(syscallno, ptr, ret);
}


static long sys_time(const struct syscall_info* call)
{
	const int syscallno = SYS_time;
	time_t* tp = (time_t*)call->args[0];

	void* ptr = prep_syscall(ASYNC_SIGNAL_SAFE);
	long ret;

	assert(syscallno == call->no);

	if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
		return raw_traced_syscall1(syscallno, tp);
	}
	ret = untraced_syscall1(syscallno, NULL);
	if (tp) {
		/* No error is possible here. */
		*tp = ret;
	}
	return commit_raw_syscall(syscallno, ptr, ret);
}

static long sys_xstat64(const struct syscall_info* call)
{
	const int syscallno = call->no;
	/* NB: this arg may be a string or an fd, but for the purposes
	 * of this generic helper we don't care. */
	long what = call->args[0];
	struct stat64* buf = (struct stat64*)call->args[1];

	/* Like open(), not arming the desched event because it's not
	 * needed for correctness, and there are no data to suggest
	 * whether it's a good idea perf-wise. */
	void* ptr = prep_syscall(ASYNC_SIGNAL_SAFE);
	struct stat64* buf2 = NULL;
	long ret;

	if (buf) {
		buf2 = ptr;
		ptr += sizeof(*buf2);
	}
	if (!start_commit_buffered_syscall(syscallno, ptr, WONT_BLOCK)) {
		return raw_traced_syscall2(syscallno, what, buf);
	}
	ret = untraced_syscall2(syscallno, what, buf2);
	if (buf2) {
		local_memcpy(buf, buf2, sizeof(*buf));
	}
	return commit_raw_syscall(syscallno, ptr, ret);
}

static long sys_write(const struct syscall_info* call)
{
	const int syscallno = SYS_write;
	int fd = call->args[0];
	const void* buf = (const void*)call->args[1];
	size_t count = call->args[2];

	void* ptr = prep_syscall(ASYNC_SIGNAL_SAFE);
	long ret;

	assert(syscallno == call->no);

	/* We always have to trap for writes to the magic save-data
	 * fd, because the rr tracer processes them specially.
	 *
	 * TODO: buffer them normally here. */
	if (RR_MAGIC_SAVE_DATA_FD == fd ||
	    !start_commit_buffered_syscall(syscallno, ptr, MAY_BLOCK)) {
		return raw_traced_syscall3(syscallno, fd, buf, count);
	}

	ret = untraced_syscall3(syscallno, fd, buf, count);

	return commit_raw_syscall(syscallno, ptr, ret);
}

static long __attribute__((unused))
vsyscall_hook(const struct syscall_info* call)
{
	switch (call->no) {
#define CASE(syscallname)						\
		case SYS_ ## syscallname: return sys_ ## syscallname(call)
	CASE(access);
	CASE(clock_gettime);
	CASE(close);
	CASE(creat);
	CASE(gettimeofday);
	CASE(open);
	CASE(read);
	CASE(readlink);
	CASE(time);
	CASE(write);
#undef CASE
	case SYS_fstat64:
	case SYS_lstat64:
	case SYS_stat64:
		return sys_xstat64(call);
	default:
		/* FIXME: pass |call| to avoid pushing these on the
		 * stack again. */
		return _raw_traced_syscall(call->no,
					   call->args[0], call->args[1],
					   call->args[2], call->args[3],
					   call->args[4], call->args[5]);
	}
}
