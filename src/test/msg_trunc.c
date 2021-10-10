/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int sockets[2];
  char out[10];

  test_assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) == 0);
  test_assert(send(sockets[0], "0123456789", 10, 0) == 10);
  memset(out, 77, sizeof(out));
  test_assert(recv(sockets[1], out, 1, MSG_TRUNC) == 10);
  test_assert(out[1] == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
