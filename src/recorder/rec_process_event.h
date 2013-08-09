/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef PROCESS_SYSCALL_H_
#define PROCESS_SYSCALL_H_

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include "../share/types.h"
#include "../share/util.h"

/**
 * Prepare |ctx| to enter |syscallno|.  Return nonzero if a
 * context-switch is allowed for |ctx|, 0 if not.
 */
int rec_prepare_syscall(struct context* ctx, int syscallno);
void rec_process_syscall(struct context* ctx, int syscall, struct flags rr_flags);

#endif /* PROCESS_SYSCALL_H_ */
