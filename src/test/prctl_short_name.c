/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Max name length is 16 bytes, *without* null terminator. */
#define PRNAME_NUM_BYTES 16

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  char* p = (char*)mmap(NULL, 2 * page_size, PROT_READ | PROT_WRITE,
                        MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  char prname[PRNAME_NUM_BYTES] = "";

  test_assert(p != MAP_FAILED);
  test_assert(0 == munmap(p + page_size, page_size));
  strcpy(p + page_size - 5, "name");
  test_assert(0 == prctl(PR_SET_NAME, p + page_size - 5));

  test_assert(0 == prctl(PR_GET_NAME, prname));
  test_assert(!strcmp(prname, "name"));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
