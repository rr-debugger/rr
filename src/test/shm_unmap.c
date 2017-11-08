/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  void* p;
  size_t page_size = sysconf(_SC_PAGESIZE);
  int shmid = shmget(IPC_PRIVATE, page_size * 3, 0666);
  test_assert(shmid >= 0);

  p = shmat(shmid, NULL, 0);
  test_assert(p != (void*)-1);
  test_assert(munmap(p, page_size) == 0);
  test_assert(shmdt(p) == 0);

  p = shmat(shmid, NULL, 0);
  test_assert(p != (void*)-1);
  test_assert(munmap(p + page_size, page_size) == 0);
  test_assert(shmdt(p) == 0);

  test_assert(0 == shmctl(shmid, IPC_RMID, NULL));

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
