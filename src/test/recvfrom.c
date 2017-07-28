/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static const char buf[] = "0123456789abcdefghijklmnopqrstuvwxyz";

/* Make it longer than sizeof(struct sockaddr) */
static const char sock_name[] = "sock_sock_sock_sock";
static const char sock_name2[] = "sock_sock_sock_sock_2";

int main(void) {
  struct sockaddr_un addr;
  struct sockaddr_un addr2;
  struct sockaddr_un out_addr;
  socklen_t out_addr_len;
  char out[100];
  int src;
  int dest = socket(AF_UNIX, SOCK_DGRAM, 0);
  test_assert(dest >= 0);

  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, sock_name);
  test_assert(0 == bind(dest, &addr, sizeof(addr)));

  src = socket(AF_UNIX, SOCK_DGRAM, 0);
  test_assert(src >= 0);

  test_assert(36 == sendto(src, buf, 36, 0, &addr, sizeof(addr)));
  out_addr_len = sizeof(out_addr);
  test_assert(36 ==
              recvfrom(dest, out, sizeof(out), 0, &out_addr, &out_addr_len));
  test_assert(0 == memcmp(buf, out, 36));
  test_assert(0 == out_addr_len);

  addr2.sun_family = AF_UNIX;
  strcpy(addr2.sun_path, sock_name2);
  test_assert(0 == bind(src, &addr2, sizeof(addr2)));

  test_assert(36 == sendto(src, buf, 36, 0, &addr, sizeof(addr)));
  out_addr_len = sizeof(out_addr);
  test_assert(36 ==
              recvfrom(dest, out, sizeof(out), 0, &out_addr, &out_addr_len));
  test_assert(0 == memcmp(buf, out, 36));
  test_assert(out_addr_len == 2 + sizeof(sock_name2));
  test_assert(0 == memcmp(out_addr.sun_path, sock_name2, sizeof(sock_name2)));

  test_assert(36 == sendto(src, buf, 36, 0, &addr, sizeof(addr)));
  out_addr_len = 8;
  out_addr.sun_path[9] = 'x';
  test_assert(36 ==
              recvfrom(dest, out, sizeof(out), 0, &out_addr, &out_addr_len));
  test_assert(0 == memcmp(buf, out, 36));
  test_assert(out_addr_len == 2 + sizeof(sock_name2));
  test_assert(0 == memcmp(out_addr.sun_path, sock_name2, 8));
  test_assert(out_addr.sun_path[9] == 'x');

  test_assert(0 == unlink(sock_name));
  test_assert(0 == unlink(sock_name2));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
