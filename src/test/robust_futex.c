/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int pipe_fds[2];
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
  char ch;

  test_assert(0 == pipe(pipe_fds));

  size_t page_size = sysconf(_SC_PAGESIZE);
  mutex = (pthread_mutex_t*)mmap(NULL, page_size, PROT_READ | PROT_WRITE,
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
    test_assert(1 == write(pipe_fds[1], "x", 1));
    sleep(1000000);
    return 1;
  }

  test_assert(1 == read(pipe_fds[0], &ch, 1));
  kill(child, SIGKILL);
  test_assert(child == wait(&status));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == 9);

  test_assert(EOWNERDEAD == pthread_mutex_lock(mutex));
  pthread_mutex_consistent(mutex);
  test_assert(0 == pthread_mutex_unlock(mutex));
  test_assert(0 == pthread_mutex_lock(mutex));
  test_assert(0 == pthread_mutex_unlock(mutex));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
