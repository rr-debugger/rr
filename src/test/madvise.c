/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

int main(int argc, char *argv[]) {
	size_t num_bytes = sysconf(_SC_PAGESIZE);
	int* page;
	int i;

	page = mmap(NULL, num_bytes, PROT_READ | PROT_WRITE,
		    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	test_assert(page != (void*)-1);

	for (i = 0; i < num_bytes / sizeof(*page); ++i) {
		test_assert(0 == page[i]);
		page[i] = i;
	}
	for (i = 0; i < num_bytes / sizeof(*page); ++i) {
		test_assert(page[i] == i);
	}

	madvise(page, num_bytes, MADV_DONTNEED);

	for (i = 0; i < num_bytes / sizeof(*page); ++i) {
		test_assert(0 == page[i]);
	}

	atomic_puts(" done");

	return 0;
}
