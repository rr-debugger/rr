/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

static void bad_breakpoint(void) {
	int break_here = 1;
	(void)break_here;
}

static void good_breakpoint(void) {
	int break_here = 1;
	(void)break_here;
}

int main(int argc, char** argv) {
	int num_syscalls;
	int i;

	bad_breakpoint();

	test_assert(argc == 2);
	num_syscalls = atoi(argv[1]);

	/* NB: this test assumes that gettid() produces at least one
	 * trace event per syscall. */
	atomic_printf("%d: running %d syscalls ...\n", getpid(), num_syscalls);
	for (i = 0; i < num_syscalls; ++i) {
		sys_gettid();
	}

	good_breakpoint();

	atomic_puts("EXIT-SUCCESS");
	return 0;
}
