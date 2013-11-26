/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

int main(int argc, char** argv) {
	int fd = open("/dev/random", O_RDONLY);
	char buf[128];

	test_assert(0 <= fd);
	test_assert(sizeof(buf) == read(fd, buf, sizeof(buf)));

	atomic_printf("Read %d random bytes\n", sizeof(buf));

	check_data(buf, sizeof(buf));

	atomic_puts("EXIT-SUCCESS");
	return 0;
}
