/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

static void queue_siginfo(int sig, int val) {
	siginfo_t si = { 0 };

	si.si_code = SI_QUEUE;
	si.si_pid = getpid();
	si.si_uid = geteuid();
	si.si_value.sival_int = val;
	syscall(SYS_rt_tgsigqueueinfo, getpid(), getpid(), sig, &si);
}

static void* thread(void* unused) {
	queue_siginfo(SIGUSR1, -42);
	sleep(1);
	queue_siginfo(SIGUSR2, 12345);
	return NULL;
}

static int usr1_val;
static int usr2_val;

static void handle_signal(int sig, siginfo_t* si, void* ctx) {
	int val = si->si_value.sival_int;
	if (SIGUSR1 == sig) {
		usr1_val = val;
	} else if (SIGUSR2 == sig) {
		usr2_val = val;
	} else {
		assert("Unexpected signal" && 0);
	}
}

int main(int argc, char *argv[]) {
	struct sigaction sa = {{ 0 }};
	pthread_t t;
	sigset_t mask, pending;
	int err;
	struct timespec ts;
	siginfo_t si = { 0 };

	sa.sa_sigaction = handle_signal;
	sa.sa_flags |= SA_SIGINFO;
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);

	pthread_create(&t, NULL, thread, NULL);

	sigemptyset(&mask);
	sigsuspend(&mask);
	err = errno;
	test_assert(EINTR == err);
	test_assert(-42 == usr1_val);

	sigpending(&pending);
	atomic_printf("USR1 pending? %s; USR2 pending? %s\n",
		      sigismember(&pending, SIGUSR1) ? "yes" : "no",
		      sigismember(&pending, SIGUSR2) ? "yes" : "no");

	sigemptyset(&pending);
	sigaddset(&pending, SIGUSR1);
	sigaddset(&pending, SIGUSR2);
	ts.tv_sec = 5;
	ts.tv_nsec = 0;
	err = sigtimedwait(&pending, &si, &ts);
	atomic_printf("Signal %d became pending\n", err);
	assert(SIGUSR2 == err);
	assert(12345 == si.si_value.sival_int);

	atomic_puts("EXIT-SUCCESS");
	return 0;
}
