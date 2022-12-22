/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#define RR_IMPLEMENT_PRELOAD

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "preload_interface.h"
#include "syscallbuf.h"

#define PTHREAD_MUTEX_PRIO_INHERIT_NP 32

#define DOUBLE_UNDERSCORE_PTHREAD_LOCK_AVAILABLE 1
#ifdef __GLIBC_PREREQ
#if __GLIBC_PREREQ(2, 34)
#undef DOUBLE_UNDERSCORE_PTHREAD_LOCK_AVAILABLE
#endif
#endif

#ifndef __BIONIC__

// Use an old version of dlsym so this code still works when built against glibc > 2.34
// but loaded into a process linking a pre-2.34 glibc.
#ifdef __x86_64__
__asm__(".symver dlsym,dlsym@GLIBC_2.2.5");
#elif defined(__i386__)
__asm__(".symver dlsym,dlsym@GLIBC_2.0");
#endif

static int (*real_pthread_mutex_init)(void* mutex, const void* attr);
static int (*real_pthread_mutex_lock)(void* mutex);
static int (*real_pthread_mutex_trylock)(void* mutex);
static int (*real_pthread_mutex_timedlock)(void* mutex,
                                           const struct timespec* abstime);
static int (*real_pthread_mutexattr_setprotocol)(void* attr, int protocol);

static void __attribute__((constructor)) init_override(void) {
  real_pthread_mutex_init = dlsym(RTLD_NEXT, "pthread_mutex_init");
  real_pthread_mutex_lock = dlsym(RTLD_NEXT, "pthread_mutex_lock");
  real_pthread_mutex_trylock = dlsym(RTLD_NEXT, "pthread_mutex_trylock");
  real_pthread_mutex_timedlock = dlsym(RTLD_NEXT, "pthread_mutex_timedlock");
  real_pthread_mutexattr_setprotocol = dlsym(RTLD_NEXT, "pthread_mutexattr_setprotocol");
}

static void fix_mutex_kind(pthread_mutex_t* mutex) {
  /* Disable priority inheritance. */
  mutex->__data.__kind &= ~PTHREAD_MUTEX_PRIO_INHERIT_NP;
}

#ifdef DOUBLE_UNDERSCORE_PTHREAD_LOCK_AVAILABLE
/*
 * We need to able to call directly to __pthread_mutex_lock and
 * __pthread_mutex_trylock because setting up our indirect function pointers
 * calls dlsym which itself can call pthread_mutex_lock (e.g. via application
 * code overriding malloc/calloc to use a pthreads-based implementation).
 * So before our pointers are set up, call these.
 *
 * If we're building against glibc 2.34 *but* we get run against a binary
 * linking with glibc < 2.34 *and* the application overrides malloc to use
 * pthreads-based synchronization then this won't work and we lose. Let's
 * hope this doesn't happen.
 */
extern int __pthread_mutex_init(pthread_mutex_t* mutex,
                                const pthread_mutexattr_t* attr);
extern int __pthread_mutex_lock(pthread_mutex_t* mutex);
extern int __pthread_mutex_trylock(pthread_mutex_t* mutex);
#endif

int pthread_mutex_init(pthread_mutex_t* mutex,
                       const pthread_mutexattr_t* attr) {
  int ret;
  pthread_mutexattr_t realattr;

  if (attr) {
    /* We wish to enforce the use of plain (no PI) mutex to avoid
     * needing to handle PI futex() operations.
     * We also wish to ensure that pthread_mutexattr_getprotocol()
     * still returns the requested protocol.
     * So we copy the attribute and force PTHREAD_PRIO_NONE.
     */
    memcpy(&realattr, attr, sizeof(realattr));
    // We assume dlsym doesn't call pthread_mutex_init with attributes.
    // We avoid calling pthread_mutexattr_setprotocol (and any other pthread functions)
    // directly because that won't work when we're built against glibc 2.34 but loaded
    // into a process using glibc < 2.34. (pthread functions got a symbol version bump
    // in 2.34.)
    if (!real_pthread_mutexattr_setprotocol) {
      real_pthread_mutexattr_setprotocol = dlsym(RTLD_NEXT, "pthread_mutexattr_setprotocol");
    }
    ret = real_pthread_mutexattr_setprotocol(&realattr, PTHREAD_PRIO_NONE);
    if (ret) {
      return ret;
    }
    attr = &realattr;
  }
  if (!real_pthread_mutex_init) {
#ifdef DOUBLE_UNDERSCORE_PTHREAD_LOCK_AVAILABLE
    return __pthread_mutex_init(mutex, attr);
#else
    real_pthread_mutex_init = dlsym(RTLD_NEXT, "pthread_mutex_init");
#endif
  }
  return real_pthread_mutex_init(mutex, attr);
}

/* Prevent use of lock elision; Haswell's TSX/RTM features used by
   lock elision increment the rbc perf counter for instructions which
   are later rolled back if the transaction fails. */
int pthread_mutex_lock(pthread_mutex_t* mutex) {
  fix_mutex_kind(mutex);
  if (!real_pthread_mutex_lock) {
#ifdef DOUBLE_UNDERSCORE_PTHREAD_LOCK_AVAILABLE
    return __pthread_mutex_lock(mutex);
#else
    real_pthread_mutex_lock = dlsym(RTLD_NEXT, "pthread_mutex_lock");
#endif
  }
  return real_pthread_mutex_lock(mutex);
}

int pthread_mutex_timedlock(pthread_mutex_t* mutex,
                            const struct timespec* abstime) {
  fix_mutex_kind(mutex);
  /* No __pthread_mutex_timedlock stub exists, so we have to use the
   * indirect call no matter what.
   */
  if (!real_pthread_mutex_timedlock) {
    real_pthread_mutex_timedlock = dlsym(RTLD_NEXT, "pthread_mutex_timedlock");
  }
  return real_pthread_mutex_timedlock(mutex, abstime);
}

int pthread_mutex_trylock(pthread_mutex_t* mutex) {
  fix_mutex_kind(mutex);
  if (!real_pthread_mutex_trylock) {
#ifdef DOUBLE_UNDERSCORE_PTHREAD_LOCK_AVAILABLE
    return __pthread_mutex_trylock(mutex);
#else
    real_pthread_mutex_trylock = dlsym(RTLD_NEXT, "pthread_mutex_trylock");
#endif
  }
  return real_pthread_mutex_trylock(mutex);
}

#endif

typedef void* Dlopen(const char* filename, int flags);

void* dlopen(const char* filename, int flags) {
  // Give up our timeslice now. This gives us a full timeslice to
  // execute the dlopen(), reducing the chance we'll hit
  // https://sourceware.org/bugzilla/show_bug.cgi?id=19329.
  Dlopen* f_ptr = (Dlopen*)dlsym(RTLD_NEXT, "dlopen");
  sched_yield();
  return f_ptr(filename, flags);
}

/** Disable XShm since rr doesn't work with it */
int XShmQueryExtension(__attribute__((unused)) void* dpy) { return 0; }

/** Make sure XShmCreateImage returns null in case an application doesn't do
    extension checks first. */
void* XShmCreateImage(__attribute__((unused)) register void* dpy,
                      __attribute__((unused)) register void* visual,
                      __attribute__((unused)) unsigned int depth,
                      __attribute__((unused)) int format,
                      __attribute__((unused)) char* data,
                      __attribute__((unused)) void* shminfo,
                      __attribute__((unused)) unsigned int width,
                      __attribute__((unused)) unsigned int height) {
  return 0;
}

RR_HIDDEN char impose_syscall_delay;
RR_HIDDEN char impose_spurious_desched;

/**
 * This is for testing purposes only.
 */
void delayed_syscall(struct syscall_info* info) {
  impose_syscall_delay = 1;
  /* Make sure 'result' is used so it's not optimized out! */
  syscall(info->no, info->args[0], info->args[1], info->args[2], info->args[3],
          info->args[4], info->args[5]);
  impose_syscall_delay = 0;
}

/**
 * This is for testing purposes only.
 * Note that this must be defined outside of the syscallbuf code.
 * Otherwise, the signal recording code may expect exit from this function
 * to trigger the syscallbuf exit breakpoint.
 */
void* syscallbuf_ptr(void) {
  return ((struct preload_thread_locals*)PRELOAD_THREAD_LOCALS_ADDR)->buffer;
}

/**
 * This is for testing purposes only.
 */
void spurious_desched_syscall(struct syscall_info* info) {
  impose_spurious_desched = 1;
  /* Make sure 'result' is used so it's not optimized out! */
  syscall(info->no, info->args[0], info->args[1], info->args[2], info->args[3],
          info->args[4], info->args[5]);
  impose_spurious_desched = 0;
}

/**
 * clang's LeakSanitizer has regular threads call sched_yield() in a loop while
 * a helper thread ptrace-attaches to them. If we let sched_yield() enter the
 * syscallbuf, the helper thread sees that the regular thread SP register
 * is pointing to the syscallbuf alt-stack, outside the stack region it
 * expects, which causes it to freak out.
 * So, override sched_yield() to perform the syscall in a way that can't
 * be syscall-buffered.
 */
int sched_yield(void) {
#ifdef __i386__
  // We have no syscall hook for `syscall` followed by `inc %ecx`
  int trash;
  asm volatile ("int $0x80; inc %0" : "=c"(trash) : "a"(SYS_sched_yield));
#elif defined(__x86_64__)
  // We have no syscall hook for `syscall` followed by `inc %ecx`
  int trash;
  asm volatile ("syscall; inc %0" : "=c"(trash) : "a"(SYS_sched_yield));
#elif defined(__aarch64__)
  register long x8 __asm__("x8") = SYS_sched_yield;
  // We explicitly blacklisted syscall that follows `mov x8, 0xdc`
  // to avoid patching clone. Abuse that to prevent this from being patched.
  __asm__ __volatile__("b 1f\n\t"
                       "mov x8, 0xdc\n"
                       "1:\n\t"
                       "svc 0\n"
                       :: "r"(x8) : "x0", "x30"); // x30 = lr
#else
#error "Unknown architecture"
#endif
  return 0;
}

#ifndef __aarch64__

/**
 * glibc geteuid() can be compiled to instructions ending in "syscall; ret"
 * which sometimes can't be hooked. So override it here with something that
 * can be hooked.
 * This is not an issue on aarch64 since we only need to patch a single instruction.
 */
uid_t geteuid(void) {
#ifdef __i386__
  return syscall(SYS_geteuid32);
#else
  return syscall(SYS_geteuid);
#endif
}

static void libstdcpp_not_found(void) {
  const char msg[] = "[rr] Interposition for libstdc++ called but symbol lookups into libstdc++ failed.\n"
    "Was libstdc++ loaded with RTLD_LOCAL? Try recording with `-v LD_PRELOAD=libstdc++.so.6`.\n"
    "About to crash! ";
  syscall(SYS_write, STDERR_FILENO, msg, sizeof(msg));
}

/**
 * libstdc++3 uses RDRAND. Bypass that with this incredible hack.
 */
void _ZNSt13random_device7_M_initERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE(
    void* this, __attribute__((unused)) void* token) {
  static void (*assign_string)(void *, char*) = NULL;
  static void (*random_init)(void *, void*) = NULL;
  if (!assign_string) {
    assign_string = (void (*)(void *, char*))dlsym(RTLD_NEXT,
      "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6assignEPKc");
    if (!assign_string) {
      libstdcpp_not_found();
    }
  }
  assign_string(token, "/dev/urandom");
  if (!random_init) {
    random_init = (void (*)(void *, void*))dlsym(RTLD_NEXT, __func__);
    if (!random_init) {
      libstdcpp_not_found();
    }
  }
  random_init(this, token);
}

/**
 * gcc 4.8.4 in Ubuntu 14.04-32
 */
void _ZNSt13random_device7_M_initERKSs(void* this,
                                       __attribute__((unused)) void* token) {
  static void (*assign_string)(void *, char*) = NULL;
  static void (*random_init)(void *, void*) = NULL;
  if (!assign_string) {
    assign_string = (void (*)(void *, char*))dlsym(RTLD_NEXT,
      "_ZNSs6assignEPKc");
    if (!assign_string) {
      libstdcpp_not_found();
    }
  }
  assign_string(token, "/dev/urandom");
  if (!random_init) {
    random_init = (void (*)(void *, void*))dlsym(RTLD_NEXT, __func__);
    if (!random_init) {
      libstdcpp_not_found();
    }
  }
  random_init(this, token);
}

#endif
