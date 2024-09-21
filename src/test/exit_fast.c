/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_syscall.h"

void _start(void) {
    unbufferable_syscall(RR_exit, 77, 0, 0);
}
