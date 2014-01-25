/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"


static int create_segment(size_t num_bytes) {
	char filename[] = "/dev/shm/rr-test-XXXXXX";
	int fd = mkstemp(filename);
	unlink(filename);
	test_assert(fd >= 0);
	ftruncate(fd, num_bytes);
	return fd;
}

int main(int argc, char *argv[]) {
	size_t num_bytes = 120; /* Not a multiple of the page size */
	int fd = create_segment(num_bytes);
	int* wpage = mmap(NULL, num_bytes, PROT_WRITE, MAP_SHARED, fd, 0);
	int* rpage = mmap(NULL, num_bytes, PROT_READ, MAP_SHARED, fd, 0);
	int i;

	test_assert(wpage != (void*)-1 && rpage != (void*)-1
		    && rpage != wpage);

	close(128);

	for (i = 0; i < num_bytes / sizeof(int); ++i) {
		wpage[i] = i;
		test_assert(rpage[i] == i);
		atomic_printf("%d,", rpage[i]);
	}

	atomic_puts(" done");

	return 0;
}
