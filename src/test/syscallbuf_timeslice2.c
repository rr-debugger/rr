/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fd;
  char buf[10];
  int i;

  for (i = 0; i < 1 << 12; ++i) {
    fd = open("/dev/zero", O_RDONLY);
    read(fd, buf, sizeof(buf));
    close(fd);
    if (!(i & ((1 << 8) - 1))) {
      atomic_printf(".");
    }
  }

  atomic_puts("\nEXIT-SUCCESS");
  return 0;
}
