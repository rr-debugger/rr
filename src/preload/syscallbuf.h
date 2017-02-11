/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_SYSCALLBUF_H_
#define RR_SYSCALLBUF_H_

#define RR_HIDDEN __attribute__((visibility("hidden")))

/**
 * Represents syscall params.  Makes it simpler to pass them around,
 * and avoids pushing/popping all the data for calls.
 */
struct syscall_info {
  long no;
  long args[6];
};

RR_HIDDEN extern struct preload_globals globals;

RR_HIDDEN extern int impose_syscall_delay;

#endif /* RR_SYSCALLBUF_H_ */
