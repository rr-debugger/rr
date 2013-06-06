/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <signal.h>
#include <stdio.h>
#include <syscall.h>
#include <sys/types.h>

static pid_t gettid() {
	return syscall(SYS_gettid);
}

static int tgkill(int tgid, int tid, int sig) {
	return syscall(SYS_tgkill, tgid, tid, sig);
}

static void sighandler(int sig) {
	printf("Task %d got signal %d\n", gettid(), sig);
}

int main(int argc, char *argv[]) {
	signal(SIGUSR1, sighandler);
	signal(SIGUSR2, sighandler);
	tgkill(getpid(), gettid(), SIGUSR1);
	tgkill(getpid(), gettid(), SIGUSR2);
	return 0;
}
