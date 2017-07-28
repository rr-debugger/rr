/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define DUMMY_FILE "dummy.txt"

static const int magic = 0x5a5a5a5a;

static void overwrite_file(const char* path, size_t num_bytes) {
  int fd = open(path, O_TRUNC | O_RDWR, 0600);
  size_t i;

  test_assert(fd >= 0);
  for (i = 0; i < num_bytes / sizeof(magic); ++i) {
    write(fd, &magic, sizeof(magic));
  }
  close(fd);
}

int main(void) {
  size_t num_bytes = sysconf(_SC_PAGESIZE);
  int fd = open(DUMMY_FILE, O_CREAT | O_EXCL | O_RDWR, 0600);
  int* rpage;
  size_t i;

  test_assert(fd >= 0);

  overwrite_file(DUMMY_FILE, num_bytes);

  rpage = mmap(NULL, num_bytes, PROT_READ, MAP_SHARED, fd, 0);
  atomic_printf("rpage:%p\n", rpage);
  test_assert(rpage != (void*)-1);

  for (i = 0; i < num_bytes / sizeof(magic); ++i) {
    test_assert(rpage[i] == magic);
  }

  lseek(fd, 0, SEEK_SET);

  for (i = 0; i < num_bytes / sizeof(i); ++i) {
    int written;

    write(fd, &i, sizeof(i));
    written = rpage[i];
    atomic_printf("(wrote %d, read %d)", (int)i, written);
    test_assert(written == (ssize_t)i);
  }

  atomic_puts(" done");
  return 0;
}
