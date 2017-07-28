/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int cookie1;
static int cookie2;
static int cookie3;

static int COOKIE = 0x12345678;

static int do_openat(int child) {
  char buf[1024];
  int fd;
  int dir_fd = open("/proc", O_PATH);
  test_assert(dir_fd >= 0);
  sprintf(buf, "%d/mem", child);
  fd = openat(dir_fd, buf, O_RDWR);
  close(dir_fd);
  return fd;
}

static int do_open(int child) {
  char buf[1024];
  sprintf(buf, "/proc/%d/mem", child);
  return open(buf, O_RDWR);
}

static int do_cmsg_generic(int child, int use_recvmmsg) {
  int fd = do_open(child);
  /* launder it through SCM_RIGHTS */
  char ch = 0;
  struct mmsghdr msgvec;
  struct msghdr* msg = &msgvec.msg_hdr;
  struct iovec iov;
  uint8_t cbuf[CMSG_SPACE(sizeof(fd))];
  struct cmsghdr* cmsg;
  int sockfds[2];

  test_assert(0 == socketpair(AF_LOCAL, SOCK_STREAM, 0, sockfds));

  iov.iov_base = "x";
  iov.iov_len = 1;
  memset(msg, 0, sizeof(*msg));
  msg->msg_iov = &iov;
  msg->msg_iovlen = 1;
  msg->msg_control = cbuf;
  msg->msg_controllen = sizeof(cbuf);
  cmsg = CMSG_FIRSTHDR(msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
  memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
  test_assert(1 == sendmsg(sockfds[1], msg, 0));

  iov.iov_base = &ch;
  if (use_recvmmsg) {
    test_assert(1 == recvmmsg(sockfds[0], &msgvec, 1, 0, NULL));
    test_assert(1 == msgvec.msg_len);
  } else {
    test_assert(1 == recvmsg(sockfds[0], msg, 0));
  }
  test_assert('x' == ch);
  cmsg = CMSG_FIRSTHDR(msg);
  test_assert(SOL_SOCKET == cmsg->cmsg_level && SCM_RIGHTS == cmsg->cmsg_type);
  memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
  close(sockfds[0]);
  close(sockfds[1]);
  return fd;
}

static int do_cmsg(int child) { return do_cmsg_generic(child, 0); }

static int do_cmsg_recvmmsg(int child) { return do_cmsg_generic(child, 1); }

static void do_test(int (*opener)(int)) {
  pid_t child;
  int fd;
  int status;
  int pipe_fds[2];
  struct iovec iov[2];

  test_assert(0 == pipe(pipe_fds));

  child = fork();
  if (!child) {
    char ch;
    test_assert(1 == read(pipe_fds[0], &ch, 1));
    test_assert(COOKIE == cookie1);
    test_assert(COOKIE == cookie2);
    test_assert(COOKIE == cookie3);
    exit(77);
  }

  fd = opener(child);
  test_assert(fd >= 0);
  test_assert(sizeof(COOKIE) ==
              pwrite(fd, &COOKIE, sizeof(COOKIE), (off_t)&cookie1));

  iov[0].iov_base = (char*)&COOKIE;
  iov[0].iov_len = 2;
  iov[1].iov_base = (char*)&COOKIE + 2;
  iov[1].iov_len = 2;
  test_assert(sizeof(COOKIE) == pwritev(fd, iov, 2, (off_t)&cookie2));

  lseek(fd, (off_t)&cookie3, SEEK_SET);
  test_assert(sizeof(COOKIE) == write(fd, &COOKIE, sizeof(COOKIE)));

  test_assert(1 == write(pipe_fds[1], "x", 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
}

int main(void) {
  do_test(do_open);
  do_test(do_openat);
  do_test(do_cmsg);
  do_test(do_cmsg_recvmmsg);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
