/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

static const double st0 = 1;
static const double st1 = 2;
static const double st2 = 3;
static const double st3 = 4;
static const double st4 = 5;
static const double st5 = 6;
static const double st6 = 7;
static const double st7 = 8;

static const float xmm0 = 10;
static const float xmm1 = 11;
static const float xmm2 = 12;
static const float xmm3 = 13;
static const float xmm4 = 14;
static const float xmm5 = 15;
static const float xmm6 = 16;
static const float xmm7 = 17;

int main(int argc, char* argv[]) {
  __asm__ __volatile__(
      /* Push the constants in stack order so they look as
       * we expect in gdb. */
#if __i386__
      "fldl st7\n\t"
      "fldl st6\n\t"
      "fldl st5\n\t"
      "fldl st4\n\t"
      "fldl st3\n\t"
      "fldl st2\n\t"
      "fldl st1\n\t"
      "fldl st0\n\t"
      "movss xmm0, %xmm0\n\t"
      "movss xmm1, %xmm1\n\t"
      "movss xmm2, %xmm2\n\t"
      "movss xmm3, %xmm3\n\t"
      "movss xmm4, %xmm4\n\t"
      "movss xmm5, %xmm5\n\t"
      "movss xmm6, %xmm6\n\t"
      "movss xmm7, %xmm7\n\t"
#elif __x86_64__
      "fldl st7(%rip)\n\t"
      "fldl st6(%rip)\n\t"
      "fldl st5(%rip)\n\t"
      "fldl st4(%rip)\n\t"
      "fldl st3(%rip)\n\t"
      "fldl st2(%rip)\n\t"
      "fldl st1(%rip)\n\t"
      "fldl st0(%rip)\n\t"
      "movss xmm0(%rip), %xmm0\n\t"
      "movss xmm1(%rip), %xmm1\n\t"
      "movss xmm2(%rip), %xmm2\n\t"
      "movss xmm3(%rip), %xmm3\n\t"
      "movss xmm4(%rip), %xmm4\n\t"
      "movss xmm5(%rip), %xmm5\n\t"
      "movss xmm6(%rip), %xmm6\n\t"
      "movss xmm7(%rip), %xmm7\n\t"
#else
#error unexpected architecture
#endif
);

  breakpoint();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
