/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static pthread_mutex_t* mutex;

static void* run_thread(__attribute__((unused)) void* unused) {
  void* p;
  size_t len;
  syscall(SYS_get_robust_list, 0, &p, &len);
  atomic_printf("robust_list = %p, len = %d\n", p, (int)len);
  test_assert(0 == pthread_mutex_lock(mutex));
  return NULL;
}

int main(void) {
  pthread_mutexattr_t attr;
  pthread_t thread;
  pid_t child;
  int status;

  mutex = (pthread_mutex_t*)mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                                 MAP_SHARED | MAP_ANONYMOUS, -1, 0);

  pthread_mutexattr_init(&attr);
  pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST);
  pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
  pthread_mutex_init(mutex, &attr);

  pthread_create(&thread, NULL, run_thread, NULL);
  pthread_join(thread, NULL);

  test_assert(EOWNERDEAD == pthread_mutex_lock(mutex));
  pthread_mutex_consistent(mutex);
  test_assert(0 == pthread_mutex_unlock(mutex));
  test_assert(0 == pthread_mutex_lock(mutex));
  test_assert(0 == pthread_mutex_unlock(mutex));

  child = fork();
  if (!child) {
    test_assert(0 == pthread_mutex_lock(mutex));
    /* leave locked */
    _exit(77);
  }

  test_assert(child == wait(&status));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  test_assert(EOWNERDEAD == pthread_mutex_lock(mutex));
  pthread_mutex_consistent(mutex);
  test_assert(0 == pthread_mutex_unlock(mutex));
  test_assert(0 == pthread_mutex_lock(mutex));
  test_assert(0 == pthread_mutex_unlock(mutex));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
