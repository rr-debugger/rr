/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static char data[10] = "0123456789";

int main(int argc, char* argv[]) {
  int pipe_fds[2];
  struct {
    char ch[7];
  }* part1;
  struct {
    char ch[10];
  }* part2;
  struct iovec iovs[2];

  test_assert(0 == pipe(pipe_fds));
  test_assert(sizeof(data) == write(pipe_fds[1], data, sizeof(data)));
  test_assert(0 == close(pipe_fds[1]));

  ALLOCATE_GUARD(part1, 'x');
  ALLOCATE_GUARD(part2, 'y');
  iovs[0].iov_base = part1;
  iovs[0].iov_len = sizeof(*part1);
  iovs[1].iov_base = part2;
  iovs[1].iov_len = sizeof(*part2);
  test_assert(sizeof(data) == readv(pipe_fds[0], iovs, 2));
  test_assert(0 == memcmp(part1, data, sizeof(*part1)));
  test_assert(
      0 == memcmp(part2, data + sizeof(*part1), sizeof(data) - sizeof(*part1)));
  test_assert(part2->ch[sizeof(data) - sizeof(*part1)] == 'y');
  VERIFY_GUARD(part1);
  VERIFY_GUARD(part2);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
