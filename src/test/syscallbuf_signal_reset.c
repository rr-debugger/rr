/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void sighandler(__attribute__((unused)) int sig) {
  /* Must be a syscall we've already executed, otherwise patching gets in the
   * way */
  open("/dev/zero", O_RDONLY);

  atomic_puts("EXIT-SUCCESS");

  exit(0);
}

int main(void) {
  char ch;
  int fd = open("/dev/zero", O_RDONLY);

  signal(SIGSEGV, sighandler);

  read(fd, &ch, 1);

  crash_null_deref();

  return 0;
}
