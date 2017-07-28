/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define TEST_FILE "foo.txt"

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  int fd = open(TEST_FILE, O_CREAT | O_EXCL | O_RDWR, 0600);
  uint8_t* pages;

  test_assert(fd >= 0);
  test_assert(0 == ftruncate(fd, 8 * page_size));

  unlink(TEST_FILE);

  pages = mmap(NULL, 8 * page_size, PROT_WRITE, MAP_PRIVATE, fd, 0);
  test_assert(pages != (void*)-1);

  /* Unmap first page. */
  munmap(pages, page_size);
  /* Unmap third page. */
  munmap(pages + 2 * page_size, page_size);
  /* Unmap fifth page. */
  munmap(pages + 4 * page_size, page_size);

  /* Unmap first 6 page locations, leave last 2. */
  munmap(pages, 6 * page_size);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
