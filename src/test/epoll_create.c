/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fd;

  fd = epoll_create(1);
  atomic_printf("New epoll file descriptor: %d\n", fd);

  if (fd >= 0) {
    atomic_puts("EXIT-SUCCESS");
  }

  close(fd);

  return 0;
}
