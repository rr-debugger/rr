/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

int main(int argc, char* argv[]) {
  test_assert(argc == 1 || (argc == 2 && !strcmp("self", argv[1])));

  if (argc != 2) {
    atomic_printf("exec(%s, 'self') ...\n", argv[0]);

    breakpoint();
    /* No syscalls in between here. */
    execlp(argv[0], argv[0], "self", NULL);
    test_assert("Not reached" && 0);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
