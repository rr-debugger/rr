/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void sighandler(int sig, siginfo_t* si, void* uctxp) {
	assert(SIGSEGV == sig && si->si_addr == (void*)0x42);

	puts("caught segfault @0x42");
	fflush(stdout);
	_exit(0);
}

int main() {
	struct sigaction act;

	memset(&act, 0, sizeof(act));
	act.sa_sigaction = sighandler;
	act.sa_flags = SA_SIGINFO;
	sigaction(SIGSEGV, &act, NULL);

	__asm__ __volatile__("call 0x42");
	return 0;
}
