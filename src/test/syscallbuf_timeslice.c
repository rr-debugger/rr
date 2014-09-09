/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(int argc, char** argv) {
  int fd;
  char buf[1 << 12];
  int i;

  fd = open("/dev/zero", O_RDONLY);
  for (i = 0; i < 1 << 8; ++i) {
    read(fd, buf, sizeof(buf));
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
