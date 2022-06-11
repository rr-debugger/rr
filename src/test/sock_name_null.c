/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  int ret;
  socklen_t len = 0;
  test_assert(sock_fd >= 0);

  ret = getsockname(sock_fd, NULL, &len);
  test_assert(ret == 0);
  test_assert(len > 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}

