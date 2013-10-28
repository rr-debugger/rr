/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */
static void breakpoint(void) {
	__asm__ ("int $3");
	/* NB: the above instruction *must* be at line 3 in this file.
	 * Tests rely on that. */
}

#include "rrutil.h"


static void handle_sigtrap(int sig) {
	atomic_puts("caught SIGTRAP!");
	_exit(0);
}

int main(int argc, char *argv[]) {
	signal(SIGTRAP, handle_sigtrap);

	atomic_puts("raising SIGTRAP ...");

	breakpoint();

	test_assert("didn't catch trap!" && 0);

	return 0;
}
