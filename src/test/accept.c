/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void client(const struct sockaddr_un* addr) {
  int clientfd;
  struct sockaddr_un a;
  socklen_t len = sizeof(a);
  char c;

  clientfd = socket(AF_UNIX, SOCK_STREAM, 0);
  test_assert(clientfd >= 0);
  test_assert(0 == connect(clientfd, (struct sockaddr*)addr, sizeof(*addr)));

  memset(&a, 0, sizeof(a));
  test_assert(1 == recvfrom(clientfd, &c, 1, 0, &a, &len));
  atomic_printf("recvfrom() -> %c from (%d,%s) len %d\n", c, a.sun_family,
                a.sun_path, len);
  test_assert(c == '!');
  test_assert(len > 0);
  test_assert(addr->sun_family == a.sun_family);
  test_assert(!strcmp(addr->sun_path, a.sun_path));

  exit(0);
}

static void server(int use_accept4, int pass_addr) {
  struct sockaddr_un addr;
  int listenfd;
  pid_t child;
  int servefd;
  struct sockaddr_un peer_addr;
  socklen_t len = sizeof(peer_addr);
  int status;
  struct sockaddr* peer_addr_ptr =
      pass_addr ? (struct sockaddr*)&peer_addr : NULL;
  socklen_t* len_ptr = pass_addr ? &len : NULL;

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, "socket.unix", sizeof(addr.sun_path) - 1);

  test_assert(0 <= (listenfd = socket(AF_UNIX, SOCK_STREAM, 0)));
  test_assert(0 == bind(listenfd, (struct sockaddr*)&addr, sizeof(addr)));
  test_assert(0 == listen(listenfd, 1));

  if (0 == (child = fork())) {
    client(&addr);
    test_assert("Not reached" && 0);
  }

  if (use_accept4) {
    test_assert(0 <= (servefd = accept4(listenfd, peer_addr_ptr, len_ptr, 0)));
  } else {
    test_assert(0 <= (servefd = accept(listenfd, peer_addr_ptr, len_ptr)));
  }
  if (pass_addr) {
    test_assert(AF_UNIX == peer_addr.sun_family);
  }

  test_assert(1 == send(servefd, "!", 1, 0));

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && 0 == WEXITSTATUS(status));

  unlink(addr.sun_path);
  close(servefd);
  close(listenfd);
}

int main(void) {
  int use_accept4, pass_addr;
  for (use_accept4 = 0; use_accept4 <= 1; ++use_accept4) {
    for (pass_addr = 0; pass_addr <= 1; ++pass_addr) {
      server(use_accept4, pass_addr);
    }
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
