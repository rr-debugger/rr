/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(int argc, char* argv[]) {
  pid_t newsid;

  newsid = setsid();
  atomic_printf("New session ID: %d\n", newsid);

  if (newsid >= 0) {
    atomic_puts("EXIT-SUCCESS");
  }

  return 0;
}
