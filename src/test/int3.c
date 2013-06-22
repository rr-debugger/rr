/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */
static void breakpoint() {
	__asm__ ("int $3");
	/* NB: the above instruction *must* be at line 3 in this file.
	 * Tests rely on that. */
}

#include <assert.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#define test_assert(cond)  assert("FAILED if not: " && (cond))

static void handle_sigtrap(int sig) {
	puts("caught SIGTRAP!");
	fflush(stdout);
	_exit(0);
}

int main(int argc, char *argv[]) {
	signal(SIGTRAP, handle_sigtrap);

	puts("raising SIGTRAP ...");
	fflush(stdout);

	breakpoint();

	test_assert("didn't catch trap!" && 0);

	return 0;
}
