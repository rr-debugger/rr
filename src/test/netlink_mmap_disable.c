/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  int ret;
  unsigned int block_size = 16 * getpagesize();
  struct nl_mmap_req req = {
    .nm_block_size = block_size,
    .nm_block_nr = 64,
    .nm_frame_size = 16384,
    .nm_frame_nr = 64 * block_size / 16384,
  };

  if (sock < 0) {
    atomic_puts("Can't create netlink socket");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  ret = setsockopt(sock, SOL_NETLINK, NETLINK_RX_RING, &req, sizeof(req));
  test_assert(ret < 0 && errno == ENOPROTOOPT);
  ret = setsockopt(sock, SOL_NETLINK, NETLINK_TX_RING, &req, sizeof(req));
  test_assert(ret < 0 && errno == ENOPROTOOPT);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
