/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static char data[10] = "0123456789";

static void test(int use_pwritev) {
  char name[] = "/tmp/rr-readv-XXXXXX";
  int fd = mkstemp(name);
  struct {
    char ch[50];
  }* buf;
  struct iovec iovs[2];

  test_assert(fd >= 0);
  test_assert(0 == unlink(name));

  iovs[0].iov_base = data;
  iovs[0].iov_len = 7;
  iovs[1].iov_base = data + iovs[0].iov_len;
  iovs[1].iov_len = sizeof(data) - iovs[0].iov_len;
  if (use_pwritev) {
    test_assert(sizeof(data) == pwritev(fd, iovs, 2, 0));
  } else {
    test_assert(sizeof(data) == writev(fd, iovs, 2));
  }

  ALLOCATE_GUARD(buf, 'x');
  test_assert(sizeof(data) == pread(fd, buf, sizeof(*buf), 0));
  test_assert(0 == memcmp(buf, data, sizeof(data)));
  test_assert(buf->ch[sizeof(data)] == 'x');
  VERIFY_GUARD(buf);
}

int main(int argc, char* argv[]) {
  test(0);
  test(1);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
