/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  struct passwd* p = getpwnam("root");
  atomic_printf("%d\n", p ? p->pw_uid : 0);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
