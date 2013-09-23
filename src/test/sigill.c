/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"


static void sighandler(int sig) {
	atomic_printf("caught signal %d, exiting\n", sig);
	_exit(0);
}

int main(int argc, char *argv[]) {
	signal(SIGILL, sighandler);

	atomic_puts("running undefined instruction ...");
	__asm__ ("ud2");
	test_assert("should have terminated!" && 0);
	return 0;
}
