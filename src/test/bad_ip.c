/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"


static void sighandler(int sig, siginfo_t* si, void* utp) {
	test_assert(SIGSEGV == sig && si->si_addr == (void*)0x42);

	atomic_puts("caught segfault @0x42");
	_exit(0);
}

int main(void) {
	struct sigaction act;

	memset(&act, 0, sizeof(act));
	act.sa_sigaction = sighandler;
	act.sa_flags = SA_SIGINFO;
	sigaction(SIGSEGV, &act, NULL);

	__asm__ __volatile__("call 0x42");
	return 0;
}
