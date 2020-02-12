/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void check_mapping(int* page, int magic, ssize_t nr_ints) {
  int i;
  for (i = 0; i < nr_ints; ++i) {
    test_assert(page[i] == magic);
  }
  atomic_printf("  %p has the correct values\n", page);
}

int main(int argc, char* argv[]) {
  if (argc > 1 && strcmp(argv[1], "exit") == 0) {
    return 0;
  }

  size_t num_bytes = sysconf(_SC_PAGESIZE);
  int fd = open("temp", O_CREAT | O_EXCL | O_RDWR, 0600);
  int* rpage;

  unlink("temp");

  test_assert(fd >= 0);

  int magic = 0x5a5a5a5a;
  size_t i;

  for (i = 0; i < 3 * num_bytes / sizeof(magic); ++i) {
    pwrite64(fd, &magic, sizeof(magic), i * sizeof(magic));
  }

  rpage = mmap(NULL, num_bytes, PROT_READ, MAP_SHARED, fd, 0);
  atomic_printf("rpage:%p\n", rpage);
  test_assert(rpage != MAP_FAILED);

  magic = 0xa5a5a5a5;

  if (0 == fork()) {
    execl(argv[0], argv[0], "exit", (char*)0);
  }

  for (i = 0; i < num_bytes / sizeof(magic); ++i) {
    pwrite64(fd, &magic, sizeof(magic), i * sizeof(magic));
  }

  check_mapping(rpage, 0xa5a5a5a5, num_bytes / sizeof(*rpage));

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
