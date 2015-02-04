/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

#define SIZE (16 * PAGE_SIZE)

static int shmid;

static void before_writing(void) {}
static void after_writing(void) {}

static int run_child(void) {
  int i;
  char* p;
  char* p2;
  pid_t child2;
  int status;

  p = shmat(shmid, NULL, 0);
  test_assert(p != (char*)-1);

  before_writing();

  for (i = 0; i < SIZE; ++i) {
    test_assert(p[i] == 0);
  }
  memset(p, 'r', SIZE / 2);

  after_writing();

  p2 = shmat(shmid, NULL, 0);
  test_assert(p2 != (char*)-1);
  memset(p + SIZE / 2, 'r', SIZE / 2);
  test_assert(0 == shmdt(p));
  test_assert(0 == shmdt(p2));

  test_assert(p ==
              mmap(p, SIZE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  test_assert(p[0] == 0);

  p = shmat(shmid, p, SHM_REMAP);
  test_assert(p != (char*)-1);
  for (i = 0; i < SIZE; ++i) {
    test_assert(p[i] == 'r');
  }

  if ((child2 = fork()) == 0) {
    memset(p, 's', SIZE);
    return 0;
  }
  test_assert(child2 == waitpid(child2, &status, __WALL));
  test_assert(0 == status);
  for (i = 0; i < SIZE; ++i) {
    test_assert(p[i] == 's');
  }

  return 0;
}

int main(int argc, char* argv[]) {
  pid_t child;
  int status;

  shmid = shmget(IPC_PRIVATE, SIZE, 0666);
  test_assert(shmid >= 0);

  if ((child = fork()) == 0) {
    return run_child();
  }

  atomic_printf("child %d\n", child);

  test_assert(child == waitpid(child, &status, __WALL));
  /* delete the shm before testing status, because we want to ensure the
     segment is deleted even if the test failed. */
  test_assert(0 == shmctl(shmid, IPC_RMID, NULL));
  test_assert(status == 0);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
