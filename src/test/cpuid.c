/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

#define my_cpuid(level, a, b, c, d)                       \
  __asm__ ("xchg{l}\t{%%}ebx, %k1\n\t"                  \
           "cpuid\n\t"                                  \
           "xchg{l}\t{%%}ebx, %k1\n\t"                  \
           : "=a" (a), "=&r" (b), "=c" (c), "=d" (d)    \
           : "0" (level))

/* It seems to be important that this be in a function call.
   Without this attribute, the function is inlined and the bug disappears. */
int __attribute__ ((noinline)) cpuid_output(void)
{
	unsigned int __eax, __ebx, __ecx, __edx;
	my_cpuid(0, __eax, __ebx, __ecx, __edx);
	if (__eax > 0) {
		/* We need to use different levels here to prevent gcc optimizing away
		   the second CPUID. */
		my_cpuid(1, __eax, __ebx, __ecx, __edx);
	}
	return __eax;
}

int main(int argc, char** argv)
{
	int i;
	int sum = 0;

	getegid();
	for (i = 0; i < 1000; ++i) {
		sum += cpuid_output();
		geteuid();
	}
	atomic_printf("EXIT-SUCCESS; sum=%d\n", sum);
	return 0;
}
