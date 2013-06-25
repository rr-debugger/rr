/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define test_assert(cond)  assert("FAILED if not: " && (cond))

static int num_signals_caught;

static pid_t gettid() {
	return syscall(SYS_gettid);
}

static int tgkill(int tgid, int tid, int sig) {
	return syscall(SYS_tgkill, tgid, tid, sig);
}

static void sighandler(int sig) {
	printf("Task %d got signal %d\n", gettid(), sig);
	++num_signals_caught;
}

int main(int argc, char *argv[]) {
	signal(SIGUSR1, sighandler);
	signal(SIGUSR2, sighandler);
	tgkill(getpid(), gettid(), SIGUSR1);
	tgkill(getpid(), gettid(), SIGUSR2);

	test_assert(2 == num_signals_caught);

	puts("EXIT-SUCCESS");
	return 0;
}
