/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define FILENAME "foo.txt"

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  int fd = open(FILENAME, O_CREAT | O_EXCL | O_RDWR, 0600);
  int* wpage;
  size_t i;
  int* rpage;

  unlink(FILENAME);

  test_assert(fd >= 0);
  ftruncate(fd, page_size);

  wpage = mmap(NULL, page_size, PROT_WRITE, MAP_SHARED, fd, 0);
  test_assert(wpage != (void*)-1);
  for (i = 0; i < page_size / sizeof(int); ++i) {
    wpage[i] = i;
  }

  rpage = mmap(NULL, page_size, PROT_READ, MAP_SHARED, fd, 0);
  test_assert(rpage != (void*)-1 && wpage != rpage);

  msync(wpage, page_size, MS_INVALIDATE);

  for (i = 0; i < page_size / sizeof(int); ++i) {
    test_assert(rpage[i] == (ssize_t)i);
    atomic_printf("%d,", rpage[i]);
  }

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
