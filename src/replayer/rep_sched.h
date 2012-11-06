#ifndef REP_SCHED_H_
#define REP_SCHED_H_

#include "replayer.h"

#include "../share/trace.h"

void rep_sched_init();
int rep_sched_get_num_threads();
struct context* rep_sched_register_thread(pid_t my_tid, pid_t rec_tid);
struct context* rep_sched_get_thread();
void rep_sched_deregister_thread(struct context** context_ptr);
void rep_sched_close();


struct rep_thread_context* new_replay_context(pid_t tid);


#endif /* REP_SCHED_H_ */
