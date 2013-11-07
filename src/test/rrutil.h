/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef RRUTIL_H
#define RRUTIL_H

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define test_assert(cond)  assert("FAILED if not: " && (cond))

#if (defined(__linux__) && (defined(__i386__) || defined(__x86_64__)) \
     && defined(_BITS_PTHREADTYPES_H))
# define PTHREAD_SPINLOCK_INITIALIZER (1)
#else
# error "Sorry, pthread_spinlock_t initializer unknown for this arch."
#endif

static pthread_spinlock_t printf_lock = PTHREAD_SPINLOCK_INITIALIZER;

/**
 * Print the printf-like arguments to stdout as atomic-ly as we can
 * manage.  Async-signal-safe.  Does not flush stdio buffers (doing so
 * isn't signal safe).
 */
__attribute__((format(printf, 1, 2)))
inline static int atomic_printf(const char* fmt, ...) {
	va_list args;
	char buf[1024];
	int len;
	ssize_t ret;

	va_start(args, fmt);
	len = vsnprintf(buf, sizeof(buf) - 1, fmt, args);
	va_end(args);
	{
		/* NBB: this spin lock isn't strictly signal-safe.
		 * However, we're trading one class of fairly frequent
		 * spurious failures with stdio for what (should!) be
		 * a less frequent class of failures with this
		 * non-reentrant spinlock.
		 *
		 * If your test mysteriously hangs with 100% CPU
		 * usage, this is a potential suspect.
		 *
		 * TODO: it's possible to fix this bug, but not
		 * trivial.  Play it by ear. */
		pthread_spin_lock(&printf_lock);
		ret = write(STDOUT_FILENO, buf, len);
		pthread_spin_unlock(&printf_lock);
	}
	return ret;
}

/**
 * Write |str| on its own line to stdout as atomic-ly as we can
 * manage.  Async-signal-safe.  Does not flush stdio buffers (doing so
 * isn't signal safe).
 */
inline static int atomic_puts(const char* str) {
	return atomic_printf("%s\n", str);
}

#define fprintf(...) USE_dont_write_stderr
#define printf(...) USE_atomic_printf_INSTEAD
#define puts(...) USE_atomic_puts_INSTEAD

/**
 * Return the calling task's id.
 */
inline static pid_t sys_gettid(void) {
	return syscall(SYS_gettid);
}

#endif /* RRUTIL_H */
