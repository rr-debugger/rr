/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"


static int interrupted_sleep(void) {
	struct timespec ts = { .tv_sec = 2 };

	alarm(1);
	errno = 0;
	/* The implementation of sleep() is technically allowed to use
	 * SIGALRM, so we have to use nanosleep() for pedantry. */
	nanosleep(&ts, NULL);
	return errno;
}

static int caught_signal;
static void handle_signal(int sig) {
	++caught_signal;
}

int main(int argc, char *argv[]) {
	int err;

	signal(SIGALRM, SIG_IGN);
	err = interrupted_sleep();
	atomic_printf("No sighandler; sleep exits with errno %d\n", err);
	test_assert(0 == err);

	signal(SIGALRM, handle_signal);
	err = interrupted_sleep();
	atomic_printf("With sighandler; sleep exits with errno %d\n", err);
	test_assert(1 == caught_signal);
	test_assert(EINTR == err);

	atomic_puts("EXIT-SUCCESS");
	return 1;
}
