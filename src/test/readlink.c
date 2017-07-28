/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define BUF_SIZE 10
#define BUF2_SIZE 1000

int main(void) {
  char path[] = "rr-test-file-XXXXXX";
  int fd = mkstemp(path);
  int count;
  char link[PATH_MAX];
  char* buf = allocate_guard(BUF_SIZE, 'q');
  char* buf2 = allocate_guard(BUF2_SIZE, 'r');

  test_assert(0 <= fd);

  for (count = 0;; ++count) {
    sprintf(link, "rr-test-link-%d", count);
    int ret = symlink(path, link);
    if (ret == 0) {
      break;
    }
    test_assert(errno == EEXIST);
  }

  test_assert(BUF_SIZE == readlink(link, buf, BUF_SIZE));
  test_assert(0 == memcmp(path, buf, BUF_SIZE));
  verify_guard(BUF_SIZE, buf);

  test_assert((ssize_t)strlen(path) == readlink(link, buf2, BUF2_SIZE));
  test_assert(0 == memcmp(path, buf2, strlen(path)));
  verify_guard(BUF2_SIZE, buf2);

  test_assert(0 == unlink(path));
  test_assert(0 == unlink(link));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
