/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef REP_SCHED_H_
#define REP_SCHED_H_

#include "replayer.h"

#include "../share/trace.h"

int rep_sched_get_num_threads();
struct context* rep_sched_register_thread(pid_t my_tid, pid_t rec_tid);
struct context* rep_sched_get_thread();
struct context* rep_sched_lookup_thread(pid_t rec_tid);
/**
 * Return a freshly-allocated array of tids in |tids|, which is of
 * length |len|.  The caller is reponsible for freeing the returned
 * array.
 */
void rep_sched_enumerate_tasks(pid_t** tids, size_t* len);
void rep_sched_deregister_thread(struct context** context_ptr);

#endif /* REP_SCHED_H_ */
