/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_SYSCALLBUF_H_
#define RR_SYSCALLBUF_H_

struct timespec;

#define RR_HIDDEN __attribute__((visibility("hidden")))

RR_HIDDEN extern struct preload_globals globals;

RR_HIDDEN extern char impose_syscall_delay;
RR_HIDDEN extern char impose_spurious_desched;

RR_HIDDEN extern int (*real_pthread_mutex_lock)(void* mutex);
RR_HIDDEN extern int (*real_pthread_mutex_trylock)(void* mutex);
RR_HIDDEN extern int (*real_pthread_mutex_timedlock)(void* mutex,
                                                     const struct timespec* abstime);

#endif /* RR_SYSCALLBUF_H_ */
