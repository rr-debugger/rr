/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

#define COUNT 4

static int semid;
static char* shmem;

static int run_child(void) {
  int child2;
  int status;
  struct sembuf ops[2];
  struct timespec ts = { 0, 20000000 };
  struct timespec ts_short = { 0, 10000000 };
  struct timespec ts_long = { 10000, 0 };

  ops[0].sem_num = 0;
  ops[0].sem_op = 1;
  ops[0].sem_flg = SEM_UNDO;
  ops[1].sem_num = 1;
  ops[1].sem_op = 1;
  ops[1].sem_flg = SEM_UNDO;
  test_assert(0 == semop(semid, ops, 2));
  *shmem = 0;

  if ((child2 = fork()) == 0) {
    ops[0].sem_op = -1;
    ops[1].sem_op = -1;
    /* The semtimedop timeout is irrelevant. We're just checking that the
       syscall works. */
    test_assert(0 == semtimedop(semid, ops, 2, &ts_long));

    *shmem = 1;

    test_assert(0 == nanosleep(&ts, NULL));

    *shmem = 0;

    ops[0].sem_op = 1;
    ops[1].sem_op = 1;
    test_assert(0 == semtimedop(semid, ops, 2, &ts));

    return 0;
  }

  test_assert(0 == nanosleep(&ts_short, NULL));

  ops[0].sem_op = -1;
  ops[1].sem_op = -1;
  test_assert(0 == semop(semid, ops, 2));

  test_assert(*shmem == 0);

  ops[0].sem_op = 1;
  ops[1].sem_op = 1;
  test_assert(0 == semop(semid, ops, 2));

  test_assert(child2 == waitpid(child2, &status, __WALL));
  test_assert(0 == status);

  return 0;
}

int main(int argc, char* argv[]) {
  pid_t child;
  int status;

  shmem = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
               MAP_ANONYMOUS | MAP_SHARED, -1, 0);
  test_assert(shmem != (void*)-1);

  semid = semget(IPC_PRIVATE, COUNT, 0666);
  test_assert(semid >= 0);

  if ((child = fork()) == 0) {
    return run_child();
  }

  atomic_printf("child %d\n", child);

  test_assert(child == waitpid(child, &status, __WALL));
  /* delete the sem before testing status, because we want to ensure the
     segment is deleted even if the test failed. */
  test_assert(0 == semctl(semid, 0, IPC_RMID, NULL));
  test_assert(status == 0);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
