#ifndef COUNTERS_H_
#define COUNTERS_H_

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>

#include <sys/ioctl.h>
#include <linux/perf_event.h>

#include "types.h"

typedef struct _hpc_event
{
	struct perf_event_attr attr;
	int fd;
} hpc_event_t;

struct hpc_context {
	pid_t tid;
	int started;

	hpc_event_t rbc_down;
	hpc_event_t rbc_up;
	hpc_event_t page_faults;
	hpc_event_t hw_int;

	size_t hpc_map_size;
	struct perf_event_mmap_page *hpc_mmap;
};



void init_libpfm();
void libpfm_event_encoding(struct perf_event_attr* attr, const char* event_str, int hw_event);
void close_libpfm();

void init_hpc(struct context *ctx);
void destry_hpc(struct context *ctx);
void start_hpc(struct context *ctx, uint64_t val);
void stop_hpc(struct context *ctx);
void reset_hpc(struct context *ctx, uint64_t val);
void stop_hpc_down(struct context *ctx);
int pending_rbc_down(struct hpc_context *counters);

uint64_t read_page_faults(struct hpc_context *counters);
uint64_t read_rbc_up(struct hpc_context *counters);
uint64_t read_rbc_down(struct hpc_context *counters);
uint64_t read_hw_int(struct hpc_context* counters);


#define STOP_COUNTER(fd) \
	if (ioctl(fd,PERF_EVENT_IOC_DISABLE, 0) < 0) { \
		perror("error stopping counter\n"); \
		sys_exit(); \
	}


#define START_COUNTER(pid,group_fd,name) \
	name.fd = syscall(336,&(name.attr),pid,-1,group_fd,0); \
    if (name.fd < 0) {perror("failed to initialize hpc\n"); fflush(stdout); exit(-1);} \
	if (ioctl(name.fd,PERF_EVENT_IOC_ENABLE,0) < 0) { \
		perror("failed to start hpc\n"); \
		sys_exit(); \
	}

#define READ_COUNTER(fd,tmp,size) \
		ssize_t ret = read(fd,tmp,size); \
		assert(ret == size);

#endif /* COUNTERS_H_ */
