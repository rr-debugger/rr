/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define MAGIC 0x1cd00d00

static void child(int sock, int fd_minus_one) {
  struct sockaddr addr;
  int fd;
  struct msghdr msg;
  union {
    int ints[2];
    uint8_t bytes[sizeof(int[2])];
  } mbuf;
  struct iovec iov;
  /* make cbuf bigger than necessary so we can test that the correct
     value is written back (the amount actually written by the kernel) */
  uint8_t cbuf[CMSG_SPACE(sizeof(fd)) + 77];
  const struct cmsghdr* cmsg;
  int zero = ~0;
  ssize_t nread;

  memset(&msg, 0, sizeof(msg));
  memset(&addr, 0x51, sizeof(addr));
  msg.msg_name = &addr;
  msg.msg_namelen = sizeof(addr);

  mbuf.ints[0] = mbuf.ints[1] = ~MAGIC;
  iov.iov_base = mbuf.bytes;
  iov.iov_len = sizeof(mbuf);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cbuf;
  msg.msg_controllen = sizeof(cbuf);
  msg.msg_flags = -1;

  atomic_printf("c: receiving msg ...\n");
  nread = recvmsg(sock, &msg, 0);

  atomic_printf("c:   ... got %#x (%zd bytes), %zu control bytes\n",
                mbuf.ints[0], nread, msg.msg_controllen);
  test_assert(nread == sizeof(mbuf.ints[0]));
  test_assert(MAGIC == mbuf.ints[0]);
  test_assert(~MAGIC == mbuf.ints[1]);
  test_assert(msg.msg_controllen == CMSG_SPACE(sizeof(fd)));

  atomic_printf("c:   ... and %d name bytes\n", msg.msg_namelen);
  test_assert(0 == msg.msg_namelen);

  atomic_printf("c:  ... and flags %d\n", msg.msg_flags);
  test_assert(0 == msg.msg_flags);

  cmsg = CMSG_FIRSTHDR(&msg);
  test_assert(SOL_SOCKET == cmsg->cmsg_level && SCM_RIGHTS == cmsg->cmsg_type);
  memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
  atomic_printf("c:   ... and fd %d; should have received %d\n", fd,
                fd_minus_one + 1);
  test_assert(fd - 1 == fd_minus_one || fd - 2 == fd_minus_one);

  atomic_printf("c: reading from /dev/zero ...\n");
  nread = read(fd, &zero, sizeof(zero));
  atomic_printf("c:   ... got %d (%zd bytes) %s\n", zero, nread,
                strerror(errno));
  test_assert(0 == zero);

  exit(0);
}

int main(void) {
  int sockfds[2];
  int sock;
  pid_t c;
  int fd;
  struct msghdr msg;
  int mbuf = MAGIC;
  struct iovec iov;
  uint8_t cbuf[CMSG_SPACE(sizeof(fd))];
  struct cmsghdr* cmsg;
  ssize_t nsent;
  int err;
  int status;

  memset(&msg, 0, sizeof(msg));
  test_assert(0 == socketpair(AF_LOCAL, SOCK_STREAM, 0, sockfds));
  sock = sockfds[0];

  fd = open("/dev/null", O_WRONLY);

  if (0 == (c = fork())) {
    child(sockfds[1], fd);
    test_assert("Not reached" && 0);
  }

  usleep(500000);
  fd = open("/dev/zero", O_RDONLY);

  iov.iov_base = &mbuf;
  iov.iov_len = sizeof(mbuf);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  msg.msg_control = cbuf;
  msg.msg_controllen = sizeof(cbuf);
  cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
  memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));

  atomic_printf("P: sending %#x with fd %d ...\n", mbuf, fd);
  nsent = sendmsg(sock, &msg, 0);
  err = errno;
  atomic_printf("P:   ... sent %zd bytes (%s/%d)\n", nsent, strerror(err), err);
  test_assert(0 < nsent);

  atomic_printf("P: waiting on child %d ...\n", c);
  test_assert(c == waitpid(c, &status, 0));
  test_assert(WIFEXITED(status) && 0 == WEXITSTATUS(status));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
