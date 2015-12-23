/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_REP_PROCESS_EVENT_H_
#define RR_REP_PROCESS_EVENT_H_

#include "TraceStream.h"

class Task;
struct ReplayTraceStep;

/**
 * Call this when |t| has just entered a syscall.  At this point, data
 * saved at |rec_before_record_syscall_entry()| can be restored.
 */
void rep_after_enter_syscall(Task* t, int syscallno);

/**
 * Process pending syscall. Call this when |t| is about to enter or exit
 * a syscall.
 */
void rep_process_syscall(Task* t, ReplayTraceStep* step);

/**
 * Process an EV_GROW_MAP event. These are like mmap syscalls, so handled
 * in replay_syscall.
 */
void process_grow_map(Task* t);

#endif /* RR_REP_PROCESS_EVENT_H_ */
