/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

int main(int argc, char *argv[]) {
	int fd;

	fd = epoll_create(1);
	atomic_printf("New epoll file descriptor: %d\n", fd);

	if (fd >= 0) {
		atomic_puts("EXIT-SUCCESS");
	}

	close(fd);

	return 0;
}
