/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(void) {
  int ret;
  pid_t pgrp = 0;

  ret = ioctl(STDIN_FILENO, TIOCGPGRP, &pgrp);
  atomic_printf("TIOCGPGRP returned process group %d (ret:%d)\n", pgrp, ret);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
