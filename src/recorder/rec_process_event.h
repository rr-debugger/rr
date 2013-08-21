/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef PROCESS_SYSCALL_H_
#define PROCESS_SYSCALL_H_

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include "../share/types.h"
#include "../share/util.h"

/**
 * Prepare |t| to enter |syscallno|.  Return nonzero if a
 * context-switch is allowed for |t|, 0 if not.
 */
int rec_prepare_syscall(struct task* t, int syscallno);
void rec_process_syscall(struct task* t, int syscall);

#endif /* PROCESS_SYSCALL_H_ */
