#ifndef TRACE_H_
#define TRACE_H_

#include <stdint.h>
#include <sys/user.h>

#include "../share/types.h"


#define STATE_SYSCALL_ENTRY		0
#define STATE_SYSCALL_EXIT		1

#define SEED_SIZE				16

#define SIG_SEGV_RDTSC 			-128
#define USR_EXIT				-129
#define USR_SCHED				-130
#define USR_NEW_RAWDATA_FILE	-131



void init_write_trace(const char* path);
void close_trace();

#endif /* READ_TRACE_H_ */
