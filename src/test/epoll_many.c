/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define BUFFER_SIZE 1024*1024

int main(void) {
  int fd;
  int pipe_fds[2];
  size_t page_size = sysconf(_SC_PAGESIZE);
  struct epoll_event event = { EPOLLIN | EPOLLET, { 0 } };
  char* p = (char*)mmap(NULL, BUFFER_SIZE,
    PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  test_assert(p != MAP_FAILED);
  test_assert(0 == munmap(p + page_size, page_size));

  fd = epoll_create(1);
  test_assert(fd >= 0);
  test_assert(0 == pipe(pipe_fds));
  test_assert(0 == epoll_ctl(fd, EPOLL_CTL_ADD, pipe_fds[0], &event));
  test_assert(0 == epoll_wait(fd, (struct epoll_event*)p,
      BUFFER_SIZE/sizeof(struct epoll_event), 1));

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
