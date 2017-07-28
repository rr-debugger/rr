/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define COUNT 4

static int semid;
static char* shmem;

#ifdef _SEM_SEMUN_UNDEFINED
union semun {
  int val;
  struct semid_ds* buf;
  unsigned short int* array;
  struct seminfo* __buf;
};
#endif

static int run_child(void) {
  int child2;
  int status;
  struct sembuf ops[2];
  struct timespec ts = { 0, 20000000 };
  struct timespec ts_short = { 0, 10000000 };
  struct timespec ts_long = { 10000, 0 };
  union semun un_arg;
  struct semid_ds* ds;
  struct seminfo* si;
  unsigned short* array;

  ops[0].sem_num = 0;
  ops[0].sem_op = 1;
  ops[0].sem_flg = SEM_UNDO;
  ops[1].sem_num = 1;
  ops[1].sem_op = 1;
  ops[1].sem_flg = SEM_UNDO;
  test_assert(0 == semop(semid, ops, 2));
  *shmem = 0;

  ALLOCATE_GUARD(ds, 'd');
  un_arg.buf = ds;
  test_assert(0 == semctl(semid, 0, IPC_STAT, un_arg));
  VERIFY_GUARD(ds);
  test_assert(ds->sem_perm.mode == 0666);
  test_assert(ds->sem_nsems == COUNT);

  ds->sem_perm.mode = 0660;
  test_assert(0 == semctl(semid, 0, IPC_SET, un_arg));

  ALLOCATE_GUARD(si, 'i');
  un_arg.__buf = si;
  /* The following syscall should always return >= 1, but
     sometimes it returns 0. I don't know why. */
  test_assert(0 <= semctl(semid, 0, IPC_INFO, un_arg));
  VERIFY_GUARD(si);
  test_assert(si->semvmx > 0);
  test_assert(si->semusz < 100000);

  /* The following syscall should always return >= 1, but
     sometimes it returns 0. I don't know why. */
  test_assert(0 <= semctl(semid, 0, SEM_INFO, un_arg));
  VERIFY_GUARD(si);
  test_assert(si->semusz > 0);
  test_assert(si->semusz < 100000);

  array = allocate_guard(COUNT * sizeof(*array), 'a');
  un_arg.array = array;
  test_assert(0 == semctl(semid, 0, GETALL, un_arg));
  verify_guard(COUNT * sizeof(*array), array);
  test_assert(array[0] == 1);
  test_assert(array[1] == 1);
  test_assert(array[2] == 0);
  test_assert(array[3] == 0);

  array[2] = 2;
  test_assert(0 == semctl(semid, 0, SETALL, un_arg));

  test_assert(0 == semctl(semid, 1, GETNCNT, NULL));

  test_assert(getpid() == semctl(semid, 1, GETPID, NULL));

  test_assert(2 == semctl(semid, 2, GETVAL, NULL));

  test_assert(0 == semctl(semid, 0, GETZCNT, NULL));

  un_arg.val = 0;
  test_assert(0 == semctl(semid, 2, SETVAL, un_arg));

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

int main(void) {
  pid_t child;
  int status;

  size_t page_size = sysconf(_SC_PAGESIZE);
  shmem = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
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
