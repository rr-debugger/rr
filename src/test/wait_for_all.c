/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int do_child(void) {
  sleep(1);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}

int main(void) {
  if (!fork()) {
    return do_child();
  }

  return 0;
}
