/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_LIBC_H_
#define RR_LIBC_H_

#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

int futex(int* uaddr, int futex_op, int val, const struct timespec* timeout,
          int* uaddr2, int val3);

int printf_stderr(const char* format, ...);

#ifdef __cplusplus
}
#endif

#endif /* RR_LIBC_H_ */
