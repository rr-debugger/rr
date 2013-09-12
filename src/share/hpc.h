/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef HPC_H_
#define HPC_H_

#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif

#include <assert.h>
#include <err.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* This choice is fairly arbitrary; linux doesn't use SIGSTKFLT so we
 * hope that tracees don't either. */
#define HPC_TIME_SLICE_SIGNAL SIGSTKFLT

struct task;

typedef struct _hpc_event
{
	struct perf_event_attr attr;
	int fd;
} hpc_event_t;

struct hpc_context {
	pid_t tid;
	int started;

	hpc_event_t inst;
	hpc_event_t rbc;
	hpc_event_t page_faults;
	hpc_event_t hw_int;
};

void init_libpfm();
void libpfm_event_encoding(struct perf_event_attr* attr, const char* event_str, int hw_event);
void close_libpfm();

void init_hpc(struct task *t);
void destry_hpc(struct task *t);
void start_hpc(struct task *t, uint64_t val);
void stop_hpc(struct task *t);
void cleanup_hpc(struct task* t);
void reset_hpc(struct task *t, uint64_t val);
void stop_rbc(struct task *t);
int pending_rbc_down(struct hpc_context *counters);

uint64_t read_page_faults(struct hpc_context *counters);
uint64_t read_rbc(struct hpc_context *counters);
uint64_t read_rbc_down(struct hpc_context *counters);
uint64_t read_hw_int(struct hpc_context* counters);
uint64_t read_insts(struct hpc_context *counters);


#define STOP_COUNTER(fd) \
	if (ioctl(fd,PERF_EVENT_IOC_DISABLE, 0) < 0) { \
		perror("error stopping counter\n"); \
		sys_exit(); \
	}


#define START_COUNTER(pid,group_fd,name) \
	name.fd = syscall(__NR_perf_event_open, &(name.attr),pid,-1,group_fd,0); \
    if (name.fd < 0) {perror("failed to initialize hpc\n"); fflush(stdout); exit(-1);} \
	if (ioctl(name.fd,PERF_EVENT_IOC_ENABLE,0) < 0) { \
		perror("failed to start hpc\n"); \
		sys_exit(); \
	}

#define READ_COUNTER(fd,tmp,size)		 \
	do {					 \
		ssize_t ret = read(fd,tmp,size); \
		(void)ret;			 \
		assert(ret == size);		 \
	} while(0)

#endif /* HPC_H_ */
