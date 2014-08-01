/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

int main(int argc, char *argv[]) {
	const int syscallno = SYS_gettid;
	int var = 41;

	__asm__ __volatile__(
		"int $0x80\n\t"
		"incl %0\n\t"
		: "=m"(var)
		: "a"(syscallno));

	atomic_printf("var should be 42, is %d\n", var);

	atomic_puts("EXIT-SUCCESS");
	return 0;
}
