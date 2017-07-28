/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  int ret;
  char buf[1024];

  if (sock < 0) {
    atomic_puts("Can't create raw socket");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  memset(buf, 0, sizeof(buf));

  ret = setsockopt(sock, SOL_PACKET, PACKET_RX_RING, buf, sizeof(buf));
  test_assert(ret < 0 && errno == ENOPROTOOPT);
  ret = setsockopt(sock, SOL_PACKET, PACKET_TX_RING, buf, sizeof(buf));
  test_assert(ret < 0 && errno == ENOPROTOOPT);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
