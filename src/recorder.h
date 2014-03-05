/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef RECORDER_H_
#define RECORDER_H_

struct flags;
class Task;

void record(void);

/**
 * Record a trace-termination event, sync the trace files, and shut
 * down.  The |t| argument allows this to give task context to the
 * trace-termination event.  It should be the most-recently-known
 * executed task.
 */
void terminate_recording(Task* t = nullptr);

#endif /* RECORDER_H_ */
