/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void dump_owner(const char* tag, int fd) {
  struct f_owner_ex own;

  memset(&own, 0, sizeof(own));
  test_assert(0 == fcntl(fd, F_GETOWN_EX, &own));
  atomic_printf("%s: { type: %d, pid: %d }\n", tag, own.type, own.pid);
}

int main(void) {
  int sockfds[2];
  int fd;
  struct f_owner_ex own;

  test_assert(0 == socketpair(AF_LOCAL, SOCK_STREAM, 0, sockfds));
  fd = sockfds[0]; /* doesn't matter */

  test_assert(0 == fcntl(fd, F_SETFL, O_ASYNC));

  dump_owner("initially", fd);

  own.type = F_OWNER_TID;
  own.pid = getpid();
  test_assert(0 == fcntl(fd, F_SETOWN_EX, &own));

  dump_owner("after SETOWN_EX(TID, self)", fd);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
