/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  struct sockaddr_un addr;
  int ret;
  test_assert(fd >= 0);
  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, "/var/run/nscd/socket");
  ret = connect(fd, &addr, sizeof(addr));
  test_assert(ret < 0 && errno == EACCES);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
