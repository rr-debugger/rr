/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static char data[10] = "0123456789";

static void test(int use_preadv) {
  static const char name[] = "temp";
  int fd = open(name, O_CREAT | O_RDWR | O_EXCL, 0600);
  struct {
    char ch[7];
  } * part1;
  struct {
    char ch[10];
  } * part2;
  struct iovec iovs[2];
  ssize_t nread;

  test_assert(fd >= 0);
  test_assert(0 == unlink(name));
  test_assert(sizeof(data) == write(fd, data, sizeof(data)));

  ALLOCATE_GUARD(part1, 'x');
  ALLOCATE_GUARD(part2, 'y');
  iovs[0].iov_base = part1;
  iovs[0].iov_len = sizeof(*part1);
  iovs[1].iov_base = part2;
  iovs[1].iov_len = sizeof(*part2);
  if (use_preadv) {
    /* Work around busted preadv prototype in older libcs */
    nread = syscall(SYS_preadv, fd, iovs, 2, 0, 0);
  } else {
    test_assert(0 == lseek(fd, 0, SEEK_SET));
    nread = readv(fd, iovs, 2);
  }
  test_assert(sizeof(data) == nread);
  test_assert(0 == memcmp(part1, data, sizeof(*part1)));
  test_assert(
      0 == memcmp(part2, data + sizeof(*part1), sizeof(data) - sizeof(*part1)));
  test_assert(part2->ch[sizeof(data) - sizeof(*part1)] == 'y');
  VERIFY_GUARD(part1);
  VERIFY_GUARD(part2);
}

int main(void) {
  test(0);
  test(1);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
