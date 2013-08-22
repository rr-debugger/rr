/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

#include <signal.h>

static void handle_sigtrap(int sig) {
	atomic_puts("caught SIGTRAP!");
	_exit(0);
}

int main(int argc, char *argv[]) {
	signal(SIGTRAP, handle_sigtrap);

	atomic_puts("raising SIGTRAP ...");

	raise(SIGTRAP);

	return 0;
}
