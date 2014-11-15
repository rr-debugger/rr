/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static char data[10] = "0123456789";

int main(int argc, char* argv[]) {
  int pipe_fds[2];
  struct iovec iovs[2];
  struct { char ch[50]; }* buf;

  iovs[0].iov_base = data;
  iovs[0].iov_len = 7;
  iovs[1].iov_base = data + iovs[0].iov_len;
  iovs[1].iov_len = sizeof(data) - iovs[0].iov_len;

  test_assert(0 == pipe(pipe_fds));
  test_assert(sizeof(data) == writev(pipe_fds[1], iovs, 2));
  test_assert(0 == close(pipe_fds[1]));

  ALLOCATE_GUARD(buf, 'x');
  test_assert(sizeof(data) == read(pipe_fds[0], buf, sizeof(*buf)));
  test_assert(0 == memcmp(buf, data, sizeof(data)));
  test_assert(buf->ch[sizeof(data)] == 'x');
  VERIFY_GUARD(buf);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
