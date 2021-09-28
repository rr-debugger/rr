/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int counter_fd;

static int sys_perf_event_open(struct perf_event_attr* attr, pid_t pid, int cpu,
                               int group_fd, unsigned long flags) {
  return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

int main(void) {
  struct perf_event_attr attr;
  void* p;
  size_t page_size = sysconf(_SC_PAGESIZE);

  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.type = PERF_TYPE_SOFTWARE;
  attr.config = PERF_COUNT_SW_CPU_CLOCK;
  attr.sample_period = 1000000;
  attr.sample_type = PERF_SAMPLE_IP;

  counter_fd = sys_perf_event_open(&attr, 0 /*self*/, -1 /*any cpu*/, -1, 0);
  test_assert(0 <= counter_fd);

  p = mmap(NULL, 3*page_size, PROT_READ | PROT_WRITE, MAP_SHARED, counter_fd, 0);
  test_assert(p != MAP_FAILED);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
