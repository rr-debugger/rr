/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void check_mapping(int* page, int magic, ssize_t nr_ints) {
  int i;
  for (i = 0; i < nr_ints; ++i) {
    test_assert(page[i] == magic);
  }
  atomic_printf("  %p has the correct values\n", page);
}

int main(void) {
  size_t num_bytes = sysconf(_SC_PAGESIZE);
  int fd = open("temp", O_CREAT | O_EXCL | O_RDWR);
  int* rpage;
  pid_t child;
  int status;

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

  magic = 0x12341234;

  child = fork();
  if (!child) {
    test_assert(0 == munmap(rpage, num_bytes));

    /* Test that writing while our page is unmapped but another
       process has a page mapped works */
    pwrite64(fd, &magic, sizeof(magic), 0);

    return 77;
  }

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  check_mapping(rpage, magic, 1);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
