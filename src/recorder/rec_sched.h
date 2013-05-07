/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef SCHEDULER_H_
#define SCHEDULER_H_

#include <sched.h>
#include "../share/types.h"


void rec_sched_set_pot_blocked(int tid);
int rec_sched_get_num_threads();
struct context* get_active_thread();

void rec_sched_register_thread(pid_t parent, pid_t child);
void rec_sched_deregister_thread(struct context **ctx);
void rec_sched_set_exec_state(int tid, int state);
void rec_sched_exit_all();

#define EMPTY 			0
#define NUM_MAX_THREADS (0xffff)
#define MAX_TID			(0xfffff)

#define HASH(tid)				((tid) & NUM_MAX_THREADS)
#define GET_TID(tid)			((tid) & MAX_TID)
#define GET_STATE(tid)			((tid) >> 20)


#define EXEC_STATE_START				0x1
#define EXEC_STATE_ENTRY_SYSCALL		0x2
#define EXEC_STATE_IN_SYSCALL			0x3
#define EXEC_STATE_IN_SYSCALL_DONE		0x4


#define GET_EXEC_STATE(tid)			(tid & 0x0f000000)


#define SET_EXEC_STATE(tid,state)	(tid) &= ~0x0f000000; tid |= (state);
#define CLEAR_EXEC_STATE(tid,state)	(tid &= (~0x0f000000);)


struct rec_sched_context {
	pid_t tid;
	int idx;

	int state;
};

#endif /* SCHEDULER_H_ */
