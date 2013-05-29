/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <stdio.h>

void spin() {
	int i, dummy;

	puts("spinning");
	for (i = 1; i < (1 << 30); ++i) {
		if (0 == i % (1 << 20)) {
			putc('.', stdout);
		}
		if (0 == i % (79 * (1 << 20))) {
			putc('\n', stdout);
		}
	}
}

int main(int argc, char *argv[]) {
	spin();
	puts("done");
	return 0;
}
