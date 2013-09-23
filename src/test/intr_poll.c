/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"


static int pipefds[2];
static int poll_pipe(int timeout_ms) {
	struct pollfd pfd;

	pfd.fd = pipefds[0];
	pfd.events = POLLIN;
	errno = 0;
	return poll(&pfd, 1, timeout_ms);
}

static int caught_signal;
static void handle_signal(int sig) {
	++caught_signal;
}

int main(int argc, char *argv[]) {

	pipe(pipefds);

	signal(SIGALRM, SIG_IGN);
	alarm(1);
	atomic_puts("ignoring SIGALRM, going into poll ...");
	test_assert(0 == poll_pipe(1500) && 0 == errno);

	signal(SIGALRM, handle_signal);
	alarm(1);
	atomic_puts("handling SIGALRM, going into poll ...");
	test_assert(-1 == poll_pipe(-1) && EINTR == errno);
	test_assert(1 == caught_signal);

	atomic_puts("EXIT-SUCCESS");
	return 1;
}
