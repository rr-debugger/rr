/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  char* vdso = (char*)getauxval(AT_SYSINFO_EHDR);
  size_t page_size = sysconf(_SC_PAGESIZE);
  munmap(vdso, 4*page_size);

  pid_t child = fork();
  if (!child) {
    return 77;
  }
  int status;
  int ret = waitpid(child, &status, 0);
  test_assert(ret == child);
  test_assert(WIFEXITED(status));
  test_assert(WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
