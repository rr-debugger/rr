/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

#define DEV_RANDOM "/dev/urandom"

int main(int argc, char** argv) {
	int fd = open(DEV_RANDOM, O_RDONLY);
	char buf[128];
	ssize_t nread;

	test_assert(0 <= fd);

	nread = read(fd, buf, sizeof(buf));
	atomic_printf("Read %d random bytes (expected %d)\n",
		      nread, sizeof(buf));
	test_assert(nread == sizeof(buf));

	check_data(buf, sizeof(buf));

	atomic_puts("EXIT-SUCCESS");
	return 0;
}
