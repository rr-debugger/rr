/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

#include <signal.h>
#include <stdlib.h>

static int num_signals_caught;

static void handle_sigrt(int sig) {
	atomic_printf("Caught signal %d\n", sig);

	++num_signals_caught;
}

int main(int argc, char *argv[]) {
	int i;

	for (i = SIGRTMIN; i <= SIGRTMAX; ++i) {
		signal(i, handle_sigrt);
		raise(i);
	}

	atomic_printf("caught %d signals; expected %d\n", num_signals_caught,
	       1 + SIGRTMAX - SIGRTMIN);
	test_assert(1 + SIGRTMAX - SIGRTMIN == num_signals_caught);

	atomic_puts("EXIT-SUCCESS");
	return 0;
}
