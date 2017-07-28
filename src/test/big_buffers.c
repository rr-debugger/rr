/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define DUMMY_FILE "dummy.txt"
#define BUF_SIZE (1 << 24)

int main(void) {
  struct timeval ts;
  char* buf;
  int fd;
  int sockfds[2];
  ssize_t nread;

  gettimeofday(&ts, NULL);

  buf = xmalloc(BUF_SIZE);
  socketpair(AF_LOCAL, SOCK_STREAM, 0, sockfds);

  /* Big read() buffer. */
  fd = creat(DUMMY_FILE, 0600);
  write(fd, "foo", 3);
  close(fd);
  fd = open(DUMMY_FILE, O_RDONLY);
  unlink(DUMMY_FILE);

  nread = read(fd, buf, BUF_SIZE);
  atomic_printf("read %zu bytes: %s\n", nread, buf);
  test_assert(3 == nread && !strcmp(buf, "foo"));

  /* Big recv() buffer. */
  write(sockfds[0], "bar", 3);
  nread = recv(sockfds[1], buf, BUF_SIZE, 0);
  atomic_printf("recv'd %zu bytes: %s\n", nread, buf);
  test_assert(3 == nread && !strcmp(buf, "bar"));

  /* Big recvfrom() buffer. */
  write(sockfds[0], "baz", 3);
  nread = recvfrom(sockfds[1], buf, BUF_SIZE, 0, NULL, NULL);
  atomic_printf("recvfrom'd %zu bytes: %s\n", nread, buf);
  test_assert(3 == nread && !strcmp(buf, "baz"));

  {
    struct mmsghdr mmsg;
    struct iovec data;

    memset(&mmsg, 0, sizeof(mmsg));
    memset(&data, 0, sizeof(data));
    mmsg.msg_hdr.msg_iov = &data;
    mmsg.msg_hdr.msg_iovlen = 1;

    /* Big recvmsg() buffer. */
    data.iov_base = "foo";
    data.iov_len = 3;
    test_assert(3 <= sendmsg(sockfds[0], &mmsg.msg_hdr, 0));

    data.iov_base = buf;
    data.iov_len = BUF_SIZE;
    nread = recvmsg(sockfds[1], &mmsg.msg_hdr, 0);
    atomic_printf("recvmsg'd %zu bytes: %s\n", nread, buf);
    test_assert(3 <= nread && !strcmp(buf, "foo"));

    /* Big recvmmsg() buffer. */
    data.iov_base = "bar";
    data.iov_len = 3;
    test_assert(1 == sendmmsg(sockfds[0], &mmsg, 1, 0));

    data.iov_base = buf;
    data.iov_len = BUF_SIZE;
    test_assert(1 == recvmmsg(sockfds[1], &mmsg, 1, 0, NULL));
    nread = mmsg.msg_len;
    atomic_printf("recvmmsg'd %zu bytes: %s\n", nread, buf);
    test_assert(3 <= nread && !strcmp(buf, "bar"));
  }

  /* TODO: tests for epoll_wait() / poll() / select() (/
   * prctl()?), which are much less likely to have buffers big
   * enough to overflow scratch. */

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
