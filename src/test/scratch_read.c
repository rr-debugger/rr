/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  int scratch_size = 512 * page_size;
  int fd = open("tempfile", O_RDWR | O_CREAT | O_TRUNC, 0700);
  void* buf = mmap(NULL, scratch_size, PROT_READ | PROT_WRITE,
                   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  int ret;
  test_assert(fd >= 0);

  /* First initialize the file */
  ret = write(fd, buf, scratch_size);
  test_assert(ret == scratch_size);

  /* Now read from the file. This should attempt a clone. */
  ret = lseek(fd, 0, SEEK_SET);
  test_assert(ret == 0);
  ret = read(fd, buf, scratch_size);
  test_assert(ret == scratch_size);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
