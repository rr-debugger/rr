/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_SYSCALLBUF_H_
#define RR_SYSCALLBUF_H_

#define RR_HIDDEN __attribute__((visibility("hidden")))

RR_HIDDEN extern struct preload_globals globals;

RR_HIDDEN extern char impose_syscall_delay;
RR_HIDDEN extern char impose_spurious_desched;

#endif /* RR_SYSCALLBUF_H_ */
