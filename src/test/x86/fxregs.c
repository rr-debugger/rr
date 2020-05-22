/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

enum cpuid_requests {
  CPUID_GETFEATURES = 0x01,
};

static void cpuid(int code, int subrequest, unsigned int* a, unsigned int* c,
                  unsigned int* d) {
  asm volatile("cpuid"
               : "=a"(*a), "=c"(*c), "=d"(*d)
               : "a"(code), "c"(subrequest)
               : "ebx");
}

static __attribute__((used)) const double st0 = 1;
static __attribute__((used)) const double st1 = 2;
static __attribute__((used)) const double st2 = 3;
static __attribute__((used)) const double st3 = 4;
static __attribute__((used)) const double st4 = 5;
static __attribute__((used)) const double st5 = 6;
static __attribute__((used)) const double st6 = 7;
static __attribute__((used)) const double st7 = 8;

static __attribute__((used)) const float xmm0 = 10;
static __attribute__((used)) const float xmm1 = 11;
static __attribute__((used)) const float xmm2 = 12;
static __attribute__((used)) const float xmm3 = 13;
static __attribute__((used)) const float xmm4 = 14;
static __attribute__((used)) const float xmm5 = 15;
static __attribute__((used)) const float xmm6 = 16;
static __attribute__((used)) const float xmm7 = 17;
static __attribute__((used)) const float xmm8 = 18;
static __attribute__((used)) const float xmm9 = 19;
static __attribute__((used)) const float xmm10 = 20;
static __attribute__((used)) const float xmm11 = 21;
static __attribute__((used)) const float xmm12 = 22;
static __attribute__((used)) const float xmm13 = 23;
static __attribute__((used)) const float xmm14 = 24;
static __attribute__((used)) const float xmm15 = 25;

#define AVX_FEATURE_FLAG (1 << 28)
#define OSXSAVE_FEATURE_FLAG (1 << 27)

static int AVX_enabled;

int main(void) {
  unsigned int eax, ecx, edx;
  unsigned int required_cpuid_flags = AVX_FEATURE_FLAG | OSXSAVE_FEATURE_FLAG;

  cpuid(CPUID_GETFEATURES, 0, &eax, &ecx, &edx);
  AVX_enabled = (ecx & required_cpuid_flags) == required_cpuid_flags;

  if (!AVX_enabled) {
    atomic_puts("AVX YMM registers disabled, not tested");
  }

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
      "movss xmm8(%rip), %xmm8\n\t"
      "movss xmm9(%rip), %xmm9\n\t"
      "movss xmm10(%rip), %xmm10\n\t"
      "movss xmm11(%rip), %xmm11\n\t"
      "movss xmm12(%rip), %xmm12\n\t"
      "movss xmm13(%rip), %xmm13\n\t"
      "movss xmm14(%rip), %xmm14\n\t"
      "movss xmm15(%rip), %xmm15\n\t"
#else
#error unexpected architecture
#endif
      );

  if (AVX_enabled) {
    __asm__ __volatile__(
#if defined(__i386__) || defined(__x86_64__)
        "vinsertf128 $1,%xmm1,%ymm0,%ymm0\n\t"
        "vinsertf128 $1,%xmm2,%ymm1,%ymm1\n\t"
        "vinsertf128 $1,%xmm3,%ymm2,%ymm2\n\t"
        "vinsertf128 $1,%xmm4,%ymm3,%ymm3\n\t"
        "vinsertf128 $1,%xmm5,%ymm4,%ymm4\n\t"
        "vinsertf128 $1,%xmm6,%ymm5,%ymm5\n\t"
        "vinsertf128 $1,%xmm7,%ymm6,%ymm6\n\t"
        "vinsertf128 $1,%xmm0,%ymm7,%ymm7\n\t"
#endif
#ifdef __x86_64__
        "vinsertf128 $1,%xmm9,%ymm8,%ymm8\n\t"
        "vinsertf128 $1,%xmm10,%ymm9,%ymm9\n\t"
        "vinsertf128 $1,%xmm11,%ymm10,%ymm10\n\t"
        "vinsertf128 $1,%xmm12,%ymm11,%ymm11\n\t"
        "vinsertf128 $1,%xmm13,%ymm12,%ymm12\n\t"
        "vinsertf128 $1,%xmm14,%ymm13,%ymm13\n\t"
        "vinsertf128 $1,%xmm15,%ymm14,%ymm14\n\t"
        "vinsertf128 $1,%xmm8,%ymm15,%ymm15\n\t"
#endif
        );
  }

  breakpoint();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
