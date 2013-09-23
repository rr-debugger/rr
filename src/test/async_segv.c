/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"


static void handle_segv(int sig) {
	test_assert(SIGSEGV == sig);
	atomic_puts("caught segv, goodbye");
	exit(0);
}

int main(int argc, char *argv[]) {
	int dummy, i;

	signal(SIGSEGV, handle_segv);

	/* No syscalls after here!  (Up to the assert.) */
	for (i = 1; i < (1 << 30); ++i) {
		dummy += (dummy + i) % 9735;
	}

	test_assert("didn't catch segv!" && 0);

	return 0;
}
