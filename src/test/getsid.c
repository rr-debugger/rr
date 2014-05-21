/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

int main(int argc, char *argv[]) {
	pid_t sid1;
	pid_t sid2;

	sid1 = getsid(0);
	sid2 = getsid(sid1);
	atomic_printf("getsid(0) session ID: %d\n", sid1);
	atomic_printf("getsid(getsid(0)) session ID: %d\n", sid2);

	if (sid1 == sid2) {
		atomic_puts("EXIT-SUCCESS");
	}

	return 0;
}
