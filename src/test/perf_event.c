/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <assert.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define test_assert(cond)  assert("FAILED if not: " && (cond))

static int counter_fd;

static int sys_perf_event_open(struct perf_event_attr *attr,
			       pid_t pid, int cpu, int group_fd,
			       unsigned long flags) {
	return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static uint64_t get_desched() {
	uint64_t nr_desched;

	test_assert(sizeof(nr_desched) ==
		    read(counter_fd, &nr_desched, sizeof(nr_desched)));
	return nr_desched;
}

int main(int argc, char *argv[]) {
	struct perf_event_attr attr;
	int i;

	memset(&attr, 0, sizeof(attr));
	attr.size = sizeof(attr);
	attr.type = PERF_TYPE_SOFTWARE;
	attr.config = PERF_COUNT_SW_CONTEXT_SWITCHES;

	counter_fd =
		sys_perf_event_open(&attr, 0/*self*/, -1/*any cpu*/, -1, 0);
	test_assert(0 <= counter_fd);

	printf("num descheds: %llu\n", get_desched());
	for (i = 0; i < 5; ++i) {
		sched_yield();
		printf("after yield: %llu\n", get_desched());
	}

	puts("EXIT_SUCCESS");
	return 0;
}
