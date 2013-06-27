/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#define test_assert(cond)  assert("FAILED if not: " && (cond))

static sig_atomic_t caught_usr1;

static void handle_usr1(int sig) {
	test_assert(SIGUSR1 == sig);
	caught_usr1 = 1;
	puts("caught usr1");
}

static void breakpoint() {
	int break_here = 1;
	(void)break_here;
}

int main(int argc, char *argv[]) {
	int dummy, i;

	signal(SIGUSR1, handle_usr1);

	breakpoint();
	/* NO SYSCALLS AFTER HERE!  (Up to the assert.) */
	for (i = 1; !caught_usr1 && i < (1 << 30); ++i) {
		dummy += (dummy + i) % 9735;
	}
	test_assert(caught_usr1);

	puts("EXIT-SUCCESS");
	return 0;
}
