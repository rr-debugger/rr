/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

static int invoked_sighandler;

static void* thread(void* unused) {
	siginfo_t si = { 0 };

	si.si_code = SI_QUEUE;
	si.si_pid = getpid();
	si.si_uid = geteuid();
	si.si_value.sival_int = -42;
	syscall(SYS_rt_tgsigqueueinfo, getpid(), getpid(), SIGUSR1, &si);

	return NULL;
}

static void handle_signal(int sig, siginfo_t* si, void* ctx) {
	test_assert(-42 == si->si_value.sival_int);
	invoked_sighandler = 1;
}

int main(int argc, char *argv[]) {
	struct sigaction sa = {{ 0 }};
	pthread_t t;
	sigset_t mask;
	int err;

	sa.sa_sigaction = handle_signal;
	sa.sa_flags |= SA_SIGINFO;
	sigaction(SIGUSR1, &sa, NULL);

	pthread_create(&t, NULL, thread, NULL);

	sigemptyset(&mask);
	sigsuspend(&mask);
	err = errno;
	test_assert(EINTR == err);
	test_assert(invoked_sighandler);

	atomic_puts("EXIT-SUCCESS");
	return 0;
}
