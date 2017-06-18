/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#define RR_IMPLEMENT_PRELOAD

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "preload_interface.h"
#include "syscallbuf.h"

/* Points at the libc/pthread real_pthread_mutex_timedlock().  We wrap
 * real_pthread_mutex_timedlock(), so need to retain this pointer to call
 * out to the libc version. There is no __pthread_mutex_timedlock stub to call.
 * There are some explicitly-versioned stubs but let's not use those. */
static int (*real_pthread_mutex_timedlock)(pthread_mutex_t* mutex,
                                           const struct timespec* abstime);

#define PTHREAD_MUTEX_TYPE_MASK 3
#define PTHREAD_MUTEX_PRIO_INHERIT_NP 32

static void fix_mutex_kind(pthread_mutex_t* mutex) {
  /* Disable priority inheritance. */
  mutex->__data.__kind &= ~PTHREAD_MUTEX_PRIO_INHERIT_NP;
}

/*
 * We bind directly to __pthread_mutex_lock and __pthread_mutex_trylock
 * because setting up indirect function pointers in init_process requires
 * calls to dlsym which itself can call pthread_mutex_lock (e.g. via
 * application code overriding malloc/calloc to use a pthreads-based
 * implementation).
 */
extern int __pthread_mutex_lock(pthread_mutex_t* mutex);
extern int __pthread_mutex_trylock(pthread_mutex_t* mutex);

/* Prevent use of lock elision; Haswell's TSX/RTM features used by
   lock elision increment the rbc perf counter for instructions which
   are later rolled back if the transaction fails. */
int pthread_mutex_lock(pthread_mutex_t* mutex) {
  fix_mutex_kind(mutex);
  return __pthread_mutex_lock(mutex);
}

int pthread_mutex_timedlock(pthread_mutex_t* mutex,
                            const struct timespec* abstime) {
  fix_mutex_kind(mutex);
  /* No __pthread_mutex_timedlock stub exists, so we have to use the
   * indirect call.
   */
  if (!real_pthread_mutex_timedlock) {
    real_pthread_mutex_timedlock = dlsym(RTLD_NEXT, "pthread_mutex_timedlock");
  }
  return real_pthread_mutex_timedlock(mutex, abstime);
}

int pthread_mutex_trylock(pthread_mutex_t* mutex) {
  fix_mutex_kind(mutex);
  return __pthread_mutex_trylock(mutex);
}

/**
 * Exported glibc synonym for |sysconf()|.  We can't use |dlsym()| to
 * resolve the next "sysconf" symbol, because
 *  - dlysym usually calls malloc()
 *  - custom allocators like jemalloc may use sysconf()
 *  - if our sysconf wrapper is re-entered during initialization, it
 *    has nothing to fall back on to get the conf name, and chaos will
 *    likely ensue if we return something random.
 */
long __sysconf(int name);

/**
 *  Pretend that only 1 processor is configured/online, because rr
 *  binds all tracees to one logical CPU.
 */
long sysconf(int name) {
  switch (name) {
    case _SC_NPROCESSORS_ONLN:
    case _SC_NPROCESSORS_CONF:
      return globals.pretend_num_cores ? globals.pretend_num_cores : 1;
  }
  return __sysconf(name);
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

/**
 * glibc geteuid() can be compiled to instructions ending in "syscall; ret"
 * which can't be hooked. So override it here with something that can be hooked.
 */
uid_t geteuid(void) { return syscall(SYS_geteuid); }

typedef void* (*fopen_ptr)(const char* filename, const char* mode);

static void random_device_init_helper(void* this) {
  void** file_ptr = (void**)this;
  void* f_ptr = dlsym(RTLD_DEFAULT, "fopen");
  fopen_ptr fopen = (fopen_ptr)f_ptr;
  *file_ptr = fopen("/dev/urandom", "rb");
}

/**
 * libstdc++3 uses RDRAND. Bypass that with this incredible hack.
 */
void _ZNSt13random_device7_M_initERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE(
    void* this, __attribute__((unused)) void* token) {
  random_device_init_helper(this);
}

/**
 * gcc 4.8.4 in Ubuntu 14.04-32
 */
void _ZNSt13random_device7_M_initERKSs(void* this,
                                       __attribute__((unused)) void* token) {
  random_device_init_helper(this);
}
