/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* recvmsg() with a msg_namelen shorter than the sender's address stores only
   msg_namelen bytes of the address, and the address's full length in
   msg_namelen. */

int main(void) {
  int fds[2];
  struct sockaddr_un addr;
  socklen_t addrlen;
  unsigned char name[64];
  char buf[16];
  struct iovec iov = { buf, sizeof(buf) };
  struct msghdr msg;
  size_t i, j;

  test_assert(0 == socketpair(AF_UNIX, SOCK_DGRAM, 0, fds));
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  /* An abstract address */
  sprintf(addr.sun_path + 1, "rr-recvmsg-short-namelen-%d", getpid());
  addrlen =
      offsetof(struct sockaddr_un, sun_path) + 1 + strlen(addr.sun_path + 1);
  test_assert(0 == bind(fds[1], (struct sockaddr*)&addr, addrlen));

  for (i = 0; i < 2; ++i) {
    test_assert(5 == send(fds[1], "hello", 5, 0));
    memset(name, 0xaa, sizeof(name));
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = name;
    msg.msg_namelen = 4;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    test_assert(5 == recvmsg(fds[0], &msg, 0));
    test_assert(msg.msg_namelen == addrlen);
    test_assert(!memcmp(name, &addr, 4));
    for (j = 4; j < sizeof(name); ++j) {
      test_assert(name[j] == 0xaa);
    }
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
