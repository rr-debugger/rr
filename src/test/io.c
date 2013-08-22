/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

int main(int argc, char *argv[]) {
	char buf[32];
	int garbage_fd = 1 << 30;

	read(garbage_fd, buf, sizeof(buf));

	atomic_puts("EXIT-SUCCESS");
	return 0;
}
