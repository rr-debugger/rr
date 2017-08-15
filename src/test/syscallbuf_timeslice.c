/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void handler(__attribute__((unused)) int sig) {}

int main(void) {
  int fd;
  char buf[10];
  int i;

  signal(SIGTRAP, handler);

  fd = open("/dev/zero", O_RDONLY);
  for (i = 0; i < 1 << 12; ++i) {
    read(fd, buf, sizeof(buf));
    if (!(i & ((1 << 8) - 1))) {
      atomic_printf(".");
    }
  }

  atomic_puts("\nEXIT-SUCCESS");
  return 0;
}
