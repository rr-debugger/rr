/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef REP_PROCESS_EVENT_H_
#define REP_PROCESS_EVENT_H_

#include "../share/types.h"
#include "../share/trace.h"
#include "../share/util.h"

void rep_process_flush(struct context* ctx);
/* |redirect_stdio| is nonzero if output written to stdout/stderr
 * during recording should be tee'd during replay, zero otherwise. */
void rep_process_syscall(struct context* ctx, int syscall, int redirect_stdio);

#endif /* REP_PROCESS_EVENT_H_ */
