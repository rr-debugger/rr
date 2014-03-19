/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

static void breakpoint(void) {
	int break_here = 1;
	(void)break_here;
}

int main(int argc, char *argv[]) {
	int var = 0;

	breakpoint();

	var = 42;
	(void)var;

	atomic_puts("EXIT-SUCCESS");
	return 0;
}
