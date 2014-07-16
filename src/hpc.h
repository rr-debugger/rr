/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef RR_HPC_H_
#define RR_HPC_H_

#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif

#include <assert.h>
#include <err.h>
#include <perfmon/perf_event.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* This choice is fairly arbitrary; linux doesn't use SIGSTKFLT so we
 * hope that tracees don't either. */
#define HPC_TIME_SLICE_SIGNAL SIGSTKFLT

// Define this macro to enable perf counters that may be interesting
// for experimentation, but aren't necessary for core functionality.
//#define HPC_ENABLE_EXTRA_PERF_COUNTERS

class Task;

typedef struct {
	struct perf_event_attr attr;
	int fd;
} hpc_event_t;

struct hpc_context {
	bool started;
	int group_leader;

	hpc_event_t rbc;
#ifdef HPC_ENABLE_EXTRA_PERF_COUNTERS
	hpc_event_t inst;
	hpc_event_t page_faults;
	hpc_event_t hw_int;
#endif
};

void init_libpfm(void);
void close_libpfm(void);

void init_hpc(Task *t);
void destroy_hpc(Task *t);
void stop_hpc(Task *t);
void reset_hpc(Task *t, int64_t val);

int64_t read_rbc(struct hpc_context *counters);

#ifdef HPC_ENABLE_EXTRA_PERF_COUNTERS
int64_t read_page_faults(struct hpc_context *counters);
int64_t read_rbc_down(struct hpc_context *counters);
int64_t read_hw_int(struct hpc_context* counters);
int64_t read_insts(struct hpc_context *counters);
#endif

#endif /* HPC_H_ */
