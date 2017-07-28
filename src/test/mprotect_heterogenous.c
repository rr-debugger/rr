/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define TEST_FILE "foo.txt"

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  int fd = open(TEST_FILE, O_CREAT | O_EXCL | O_RDWR, 0600);
  uint8_t* pages;
  int ret, err;

  test_assert(fd >= 0);
  test_assert(0 == ftruncate(fd, 8 * page_size));

  unlink(TEST_FILE);

  pages = mmap(NULL, 5 * page_size, PROT_WRITE, MAP_PRIVATE, fd, 0);
  test_assert(pages != (void*)-1);

  /* Protect second page. */
  test_assert(0 == mprotect(pages + page_size, page_size, PROT_NONE));
  /* Protect fourth page. */
  test_assert(0 == mprotect(pages + 3 * page_size, page_size, PROT_NONE));
  /* Protect all five pages. */
  test_assert(0 == mprotect(pages, 5 * page_size, PROT_NONE));

  /* Unmap second page. */
  test_assert(0 == munmap(pages + page_size, page_size));
  /* Fail to protect the entire region, because one page is
   * unmapped. */
  errno = 0;
  ret = mprotect(pages, 5 * page_size, PROT_READ | PROT_WRITE);
  err = errno;
  test_assert(-1 == ret && ENOMEM == err);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
