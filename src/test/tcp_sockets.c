/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  // ipv4
  int socket_fd[3];
  socket_fd[0] = socket(AF_INET, SOCK_STREAM, 0);
  test_assert(socket_fd[0] >= 0);
  int reuseaddr = 1;
  test_assert(0 == setsockopt(socket_fd[0], SOL_SOCKET, SO_REUSEADDR, &reuseaddr,
			      sizeof(reuseaddr)));
  socket_fd[1] = socket(AF_INET, SOCK_STREAM, 0);
  test_assert(socket_fd[1] >= 0);

  struct sockaddr_storage sa;
  socklen_t sa_size = sizeof(sa);
  struct sockaddr_in* sa_in = (struct sockaddr_in*)&sa;
  sa_in->sin_family = AF_INET;
  sa_in->sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  sa_in->sin_port = 0;

  test_assert(0 == bind(socket_fd[0], (struct sockaddr*)&sa, sa_size));
  test_assert(0 == getsockname(socket_fd[0], (struct sockaddr*)&sa, &sa_size));
  test_assert(0 == listen(socket_fd[0], 1));
  test_assert(0 == connect(socket_fd[1], (struct sockaddr*)&sa, sa_size));

  socket_fd[2] = accept(socket_fd[0], (struct sockaddr*)&sa, &sa_size);
  test_assert(socket_fd[2] >= 0);

  close(socket_fd[0]);
  close(socket_fd[1]);
  close(socket_fd[2]);

  // ipv6
  socket_fd[0] = socket(AF_INET6, SOCK_STREAM, 0);
  test_assert(socket_fd[0] >= 0);
  test_assert(0 == setsockopt(socket_fd[0], SOL_SOCKET, SO_REUSEADDR, &reuseaddr,
			      sizeof(reuseaddr)));
  socket_fd[1] = socket(AF_INET6, SOCK_STREAM, 0);
  test_assert(socket_fd[1] >= 0);

  sa_size = sizeof(sa);
  struct sockaddr_in6* sa_in6 = (struct sockaddr_in6*)&sa;
  sa_in6->sin6_family = AF_INET6;
  sa_in6->sin6_addr = in6addr_loopback;
  sa_in6->sin6_port = 0;

  test_assert(0 == bind(socket_fd[0], (struct sockaddr*)&sa, sa_size));
  test_assert(0 == getsockname(socket_fd[0], (struct sockaddr*)&sa, &sa_size));
  test_assert(0 == listen(socket_fd[0], 1));
  assert(0 == connect(socket_fd[1], (struct sockaddr*)&sa, sa_size));

  socket_fd[2] = accept(socket_fd[0], (struct sockaddr*)&sa, &sa_size);
  test_assert(socket_fd[2] >= 0);

  close(socket_fd[0]);
  close(socket_fd[1]);
  close(socket_fd[2]);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
