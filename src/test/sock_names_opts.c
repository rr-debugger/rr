/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void client(const struct sockaddr_un* addr) {
  int clientfd;
  char c;
  struct sockaddr_un got_peer_addr;
  socklen_t got_peer_addr_len = sizeof(got_peer_addr);

  clientfd = socket(AF_UNIX, SOCK_STREAM, 0);
  test_assert(clientfd >= 0);
  test_assert(0 == connect(clientfd, (struct sockaddr*)addr, sizeof(*addr)));

  test_assert(0 == getpeername(clientfd, &got_peer_addr, &got_peer_addr_len));
  test_assert(got_peer_addr_len > 0 &&
              got_peer_addr_len <= sizeof(got_peer_addr));
  test_assert(0 == memcmp(&got_peer_addr, addr, got_peer_addr_len));

  test_assert(1 == read(clientfd, &c, 1));
  test_assert(c == '!');

  exit(7);
}

int main(void) {
  struct sockaddr_un addr;
  struct sockaddr_un got_name;
  socklen_t got_name_len = sizeof(got_name);
  int listenfd;
  int servefd;
  struct sockaddr_un peer_addr;
  socklen_t peer_addr_len = sizeof(peer_addr);
  pid_t child;
  int on = 1;
  int got_opt = -1;
  socklen_t got_opt_len = sizeof(got_opt);
  int status;

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, "socket.unix", sizeof(addr.sun_path) - 1);

  test_assert(0 <= (listenfd = socket(AF_UNIX, SOCK_STREAM, 0)));
  test_assert(0 == bind(listenfd, (struct sockaddr*)&addr, sizeof(addr)));

  test_assert(0 == getsockname(listenfd, &got_name, &got_name_len));
  test_assert(got_name_len > 0 && got_name_len <= sizeof(got_name));
  test_assert(0 == memcmp(&addr, &got_name, got_name_len));

  test_assert(0 == listen(listenfd, 1));
  if (0 == (child = fork())) {
    client(&addr);
    test_assert("Not reached" && 0);
  }

  test_assert(0 <= (servefd = accept(listenfd, &peer_addr, &peer_addr_len)));

  test_assert(0 == getsockopt(servefd, SOL_SOCKET, SO_PASSCRED, &got_opt,
                              &got_opt_len));
  test_assert(got_opt_len == sizeof(got_opt));
  test_assert(got_opt == 0);
  test_assert(0 ==
              setsockopt(servefd, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)));
  test_assert(0 == getsockopt(servefd, SOL_SOCKET, SO_PASSCRED, &got_opt,
                              &got_opt_len));
  test_assert(got_opt_len == sizeof(got_opt));
  test_assert(got_opt == 1);

  test_assert(1 == write(servefd, "!", 1));

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 7);

  unlink(addr.sun_path);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
