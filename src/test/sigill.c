/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

static void sighandler(int sig) {
	printf("caught signal %d, exiting\n", sig);
	fflush(stdout);
	_exit(0);
}

int main(int argc, char *argv[]) {
	signal(SIGILL, sighandler);

	puts("running undefined instruction ...");
	__asm__ ("ud2");
	assert("should have terminated!" && 0);
	return 0;
}
