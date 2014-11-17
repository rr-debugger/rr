/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static void constructor(void) __attribute__((constructor));

static void constructor(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
}

void lib_exit_success(void) { atomic_puts("EXIT-SUCCESS"); }
