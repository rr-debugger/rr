/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef REP_PROCESS_EVENT_H_
#define REP_PROCESS_EVENT_H_

struct context;
struct rep_trace_step;

/**
 * Replay up to and emulate the ioctl used to arm/disarm the desched
 * event.
 */
void rep_skip_desched_ioctl(struct context* ctx);
void rep_process_flush(struct context* ctx);
/* |redirect_stdio| is nonzero if output written to stdout/stderr
 * during recording should be tee'd during replay, zero otherwise. */
void rep_process_syscall(struct context* ctx, int redirect_stdio,
			 struct rep_trace_step* step);

#endif /* REP_PROCESS_EVENT_H_ */
