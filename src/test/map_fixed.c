/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

int main(int argc, char *argv[]) {
	size_t page_size = sysconf(_SC_PAGESIZE);
	byte* map1 = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
			  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	byte* map1_end = map1 + page_size;
	byte* map2;

	test_assert(map1 != (void*)-1);

	map2 = mmap(map1_end, page_size, PROT_READ | PROT_WRITE,
		    MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	test_assert(map2 != (void*)-1);
	test_assert(map2 == map1_end);

	atomic_puts(" done");

	return 0;
}
