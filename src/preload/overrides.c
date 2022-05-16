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

static int (*real_pthread_mutex_init)(void* mutex, const void* attr);
static int (*real_pthread_mutex_lock)(void* mutex);
static int (*real_pthread_mutex_trylock)(void* mutex);
static int (*real_pthread_mutex_timedlock)(void* mutex,
                                           const struct timespec* abstime);

static void __attribute__((constructor)) init_override(void) {
  real_pthread_mutex_init = dlsym(RTLD_NEXT, "pthread_mutex_init");
  real_pthread_mutex_lock = dlsym(RTLD_NEXT, "pthread_mutex_lock");
  real_pthread_mutex_trylock = dlsym(RTLD_NEXT, "pthread_mutex_trylock");
  real_pthread_mutex_timedlock = dlsym(RTLD_NEXT, "pthread_mutex_timedlock");
}

static void fix_mutex_kind(pthread_mutex_t* mutex) {
  /* Disable priority inheritance. */
  mutex->__data.__kind &= ~PTHREAD_MUTEX_PRIO_INHERIT_NP;
}

#ifdef DOUBLE_UNDERSCORE_PTHREAD_LOCK_AVAILABLE
/*
 * We need to able to call directly to __pthread_mutex_lock and
 * __pthread_mutex_trylock because setting up indirect function pointers
 * in init_process requires calls to dlsym which itself can call
 * pthread_mutex_lock (e.g. via application code overriding malloc/calloc
 * to use a pthreads-based implementation). So before our pointers are set
 * up, call these.
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
    ret = pthread_mutexattr_setprotocol(&realattr, PTHREAD_PRIO_NONE);
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
 */
void spurious_desched_syscall(struct syscall_info* info) {
  impose_spurious_desched = 1;
  /* Make sure 'result' is used so it's not optimized out! */
  syscall(info->no, info->args[0], info->args[1], info->args[2], info->args[3],
          info->args[4], info->args[5]);
  impose_spurious_desched = 0;
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

/**
 * clang's LeakSanitizer has regular threads call sched_yield() in a loop while
 * a helper thread ptrace-attaches to them. If we let sched_yield() enter the
 * syscallbuf, the helper thread sees that the regular thread SP register
 * is pointing to the syscallbuf alt-stack, outside the stack region it
 * expects, which causes it to freak out.
 * So, override sched_yield() to perform the syscall in a way that can't
 * be syscall-buffered. (We have no syscall hook for `syscall` followed by
 * `inc %ecx`).
 */
int sched_yield(void) {
  int trash;
#ifdef __i386__
  asm volatile ("int $0x80; inc %0" : "=c"(trash) : "a"(SYS_sched_yield));
#elif defined(__x86_64__)
  asm volatile ("syscall; inc %0" : "=c"(trash) : "a"(SYS_sched_yield));
#else
#error "Unknown architecture"
#endif
  return 0;
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
  }
  assign_string(token, "/dev/urandom");
  if (!random_init) {
    random_init = (void (*)(void *, void*))dlsym(RTLD_NEXT, __func__);
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
  }
  assign_string(token, "/dev/urandom");
  if (!random_init) {
    random_init = (void (*)(void *, void*))dlsym(RTLD_NEXT, __func__);
  }
  random_init(this, token);
}

#endif
