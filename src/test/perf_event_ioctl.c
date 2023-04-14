/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */
/* Test for performance monitoring ('perf') ioctls. */

#include "util.h"

/**
 * glibc doesn't provide a wrapper for perf_event_open syscall. Hence, we create our
 * own wrapper.
 */
static int perf_event_open(struct perf_event_attr *hw_event,
                           pid_t pid,
                           int cpu,
                           int group_fd,
                           unsigned long flags) {
  int ret;
  ret = syscall(__NR_perf_event_open,hw_event,pid,cpu,group_fd,flags);
  return ret;
}

int main(void) {
  struct perf_event_attr pe_attr;
  memset(&pe_attr,0,sizeof(pe_attr));
  pe_attr.type = PERF_TYPE_SOFTWARE;
  pe_attr.config = PERF_COUNT_SW_CPU_CLOCK;
  pe_attr.size = sizeof(struct perf_event_attr);
  pe_attr.disabled = 1;
  pe_attr.exclude_kernel = 1;
  pe_attr.exclude_hv = 1;
  pe_attr.exclude_idle = 1;
  pe_attr.read_format = PERF_FORMAT_GROUP|PERF_FORMAT_ID;

  int const fd = perf_event_open(&pe_attr,0,-1,-1,0);
  test_assert(fd >= 0);

  int ioctl_ret;

  ioctl_ret = ioctl(fd,PERF_EVENT_IOC_ENABLE,PERF_IOC_FLAG_GROUP);
  test_assert(ioctl_ret >= 0);

  ioctl_ret = ioctl(fd,PERF_EVENT_IOC_DISABLE,PERF_IOC_FLAG_GROUP);
  test_assert(ioctl_ret >= 0);

  ioctl_ret = ioctl(fd,PERF_EVENT_IOC_RESET,PERF_IOC_FLAG_GROUP);
  test_assert(ioctl_ret >= 0);

  uint64_t event_id;
  ioctl_ret = ioctl(fd,PERF_EVENT_IOC_ID,&event_id);
  test_assert(ioctl_ret >= 0);

  int const close_ret = close(fd);
  test_assert(close_ret == 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
