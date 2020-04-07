/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#define _FILE_OFFSET_BITS 64

#include "util.h"

#define TEST_FILE "foo.txt"

ssize_t get_file_size(const char* filename) {
  struct stat* st;
  ssize_t result;

  ALLOCATE_GUARD(st, 'x');
  test_assert(0 == stat(filename, st));
  result = st->st_size;
  FREE_GUARD(st);
  return result;
}

int main(void) {
  int fd;
  ssize_t size;

  fd = open(TEST_FILE, O_CREAT | O_EXCL | O_RDWR, 0600);
  test_assert(0 <= fd);

  size = get_file_size(TEST_FILE);
  atomic_printf("initial file size: %zd\n", size);
  test_assert(0 == size);

  truncate(TEST_FILE, 4096);
  size = get_file_size(TEST_FILE);
  atomic_printf("after truncate(4096): %zd\n", size);
  test_assert(4096 == size);

  ftruncate(fd, 8192);
  size = get_file_size(TEST_FILE);
  atomic_printf("after truncate(8192): %zd\n", size);
  test_assert(8192 == size);

  unlink(TEST_FILE);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
