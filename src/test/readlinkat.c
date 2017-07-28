/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define BUF_SIZE 10
#define BUF2_SIZE 1000

int main(void) {
  static const char file_path[] = "rr-test-file";
  static const char link_path[] = "rr-test-link";
  char* buf = allocate_guard(BUF_SIZE, 'q');
  char* buf2 = allocate_guard(BUF2_SIZE, 'r');

  test_assert(0 == symlink(file_path, link_path));
  test_assert(BUF_SIZE == readlinkat(AT_FDCWD, link_path, buf, BUF_SIZE));
  test_assert(0 == memcmp(file_path, buf, BUF_SIZE));
  verify_guard(BUF_SIZE, buf);

  test_assert((ssize_t)(sizeof(file_path) - 1) ==
              readlinkat(AT_FDCWD, link_path, buf2, BUF2_SIZE));
  test_assert(0 == memcmp(file_path, buf2, sizeof(file_path) - 1));
  verify_guard(BUF2_SIZE, buf2);

  test_assert(0 == unlink(link_path));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
