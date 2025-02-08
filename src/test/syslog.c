/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include <sys/klog.h>

#define BUF1_SIZE 500

int main(void) {
  int log_buf_size = klogctl(10 /* SYSLOG_ACTION_SIZE_BUFFER */, NULL, 42);
  if (log_buf_size == -1 && errno == EPERM) {
    atomic_puts("Skipping test because it requires CAP_SYSLOG");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(log_buf_size >= 0);

  char* buf1 = allocate_guard(BUF1_SIZE, '1');
  int buf2_size = log_buf_size + 10;
  char* buf2 = allocate_guard(buf2_size, '2');

  int size1 = klogctl(3 /* SYSLOG_ACTION_READ_ALL */, buf1, BUF1_SIZE);
  test_assert(size1 >= 0);
  verify_guard(BUF1_SIZE, buf1);

  int size2 = klogctl(3 /* SYSLOG_ACTION_READ_ALL */, buf2, buf2_size);
  test_assert(size2 >= 0);
  verify_guard(buf2_size, buf2);

  test_assert(size2 >= size1);
  test_assert(0 == memcmp(buf1, buf2 + (size2 - size1), size1));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
