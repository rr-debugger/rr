/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <assert.h>
#include <stdio.h>
#include <signal.h>

static void handle_sigtrap(int sig) {
	puts("caught SIGTRAP!");
	fflush(stdout);
}

int main(int argc, char *argv[]) {
	signal(SIGTRAP, handle_sigtrap);

	puts("raising SIGTRAP ...");
	fflush(stdout);

	__asm__ ("int $3");

	return 0;
}
