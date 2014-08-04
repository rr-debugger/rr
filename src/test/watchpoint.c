/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

static void breakpoint(void) {
	int break_here = 1;
	(void)break_here;
}

static int var;

static void* thread(void* unused) {
	var = 1337;
	return NULL;
}

int main(int argc, char *argv[]) {
	pthread_t t;

	breakpoint();

	var = 42;

	pthread_create(&t, NULL, thread, NULL);
	pthread_join(t, NULL);

	atomic_printf("var=%d\n", var);

	atomic_puts("EXIT-SUCCESS");
	return 0;
}
