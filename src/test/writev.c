/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include "util_internal.h"

static char data[11] = "0123456789";

static void test(int mode) {
  static const char name[] = "temp";
  int fd = open(name, O_CREAT | O_EXCL | O_RDWR, 0600);
  struct {
    char ch[50];
  } * buf;
  struct iovec iovs[2];
  ssize_t nwritten;

  test_assert(fd >= 0);
  test_assert(0 == unlink(name));

  iovs[0].iov_base = data;
  iovs[0].iov_len = 7;
  iovs[1].iov_base = data + iovs[0].iov_len;
  iovs[1].iov_len = sizeof(data) - iovs[0].iov_len;
  if (mode == 1) {
    /* Work around busted pwritev prototype in older libcs */
    nwritten = syscall(SYS_pwritev, fd, iovs, 2, 0, 0);
  } else if (mode == 2) {
    nwritten = syscall(SYS_pwritev2, fd, iovs, 2, 0, 0, 0);
  } else {
    nwritten = writev(fd, iovs, 2);
  }
  test_assert(sizeof(data) == nwritten);

  ALLOCATE_GUARD(buf, 'x');
  test_assert(sizeof(data) == pread(fd, buf, sizeof(*buf), 0));
  test_assert(0 == memcmp(buf, data, sizeof(data)));
  test_assert(buf->ch[sizeof(data)] == 'x');
  VERIFY_GUARD(buf);
}

int main(void) {
  int fd;
  struct iovec iov;
  char buf = 'a';
  ssize_t ret;

  test(0);
  test(1);
  test(2);

  /* rr rejects RWF_APPEND (0x10): the kernel would ignore the explicit
   * offset, but FileMonitor would compute it from the arguments and
   * get it wrong. Unknown flags are rejected for the same kind of
   * reason. Only rr is guaranteed to produce EINVAL here. */
  if (running_under_rr()) {
    fd = open("temp2", O_CREAT | O_RDWR | O_EXCL, 0600);
    test_assert(fd >= 0);
    test_assert(0 == unlink("temp2"));
    iov.iov_base = &buf;
    iov.iov_len = 1;
    ret = syscall(SYS_pwritev2, fd, &iov, 1, 0, 0, 0x10 /*RWF_APPEND*/);
    test_assert(ret == -1 && errno == EINVAL);
    ret = syscall(SYS_pwritev2, fd, &iov, 1, 0, 0, 0x40000000);
    test_assert(ret == -1 && errno == EINVAL);
    close(fd);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
