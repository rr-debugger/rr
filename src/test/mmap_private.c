/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#define test_assert(cond)  assert("FAILED if not: " && (cond))

static void breakpoint() {
	int break_here = 1;
}

int main(int argc, char *argv[]) {
	size_t num_bytes = sysconf(_SC_PAGESIZE);
	int fd = open(argv[0], O_RDONLY);
	int* wpage;
	int* rpage;
	int i;

	test_assert(fd >= 0);

	breakpoint();
	wpage = mmap(NULL, num_bytes, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE, fd, 0);

	breakpoint();
	rpage = mmap(NULL, num_bytes, PROT_READ,
		     MAP_PRIVATE, fd, 0);

	test_assert(wpage != (void*)-1 && rpage != (void*)-1
		    && rpage != wpage);

	breakpoint();
	for (i = 0; i < num_bytes / sizeof(int); ++i) {
		int magic;

		test_assert(wpage[i] == rpage[i]);

		magic = rpage[i] * 31 + 3;
		wpage[i] = magic;

		assert(rpage[i] != magic && wpage[i] == magic);
		printf("%d:%d,", rpage[i], wpage[i]);
	}

	puts(" done");

	return 0;
}
