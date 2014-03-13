/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

static int caught_signal;
static void handle_signal(int sig) {
	++caught_signal;
}

int main(int argc, char *argv[]) {
	int err;

	signal(SIGALRM, handle_signal);
	alarm(1);
	atomic_puts("set alarm for 1 sec from now; pausing ...");
	pause();
	err = errno;

	atomic_printf("  ... woke up with errno %s(%d)\n", strerror(err), err);
	test_assert(1 == caught_signal);
	test_assert(EINTR == err);

	atomic_puts("EXIT-SUCCESS");
	return 1;
}
