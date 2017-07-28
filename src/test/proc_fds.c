/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include <dirent.h>
#include <unistd.h>

static pthread_barrier_t bar;
static const char proc_fd_path[] = "/proc/self/fd";

static void* thread_func(__attribute__((unused)) void* name) {
  pthread_barrier_wait(&bar);
  sleep(1);
  return NULL;
}

static void close_upper_fds(void) {
  DIR* dir = opendir(proc_fd_path);
  struct dirent* ent;
  int fd;

  test_assert(dir != NULL);
  while ((ent = readdir(dir)) != NULL) {
    fd = atoi(ent->d_name);
    if (fd > 2) {
      close(fd);
    }
  }
  closedir(dir);
}

int main(void) {
  // Empirically tested to be enough to make ProcFdDirMonitor
  // repeat the getdents call.
  const int NUM_THREADS = 20;
  int i;

  // Close any non-stdio fds inherited from the environment
  close_upper_fds();

  for (i = 0; i < 15; i++) {
    dup(2);
  }

  close(RR_MAGIC_SAVE_DATA_FD);

  /* init barrier */
  pthread_barrier_init(&bar, NULL, NUM_THREADS + 1);
  /* Create independent threads each of which will execute
   * function */
  for (i = 0; i < NUM_THREADS; i++) {
    pthread_t thread;
    pthread_create(&thread, NULL, thread_func, NULL);
  }

  pthread_barrier_wait(&bar);

  const char proc_fd_path[] = "/proc/self/fd";
  int fd = syscall(SYS_open, proc_fd_path, O_DIRECTORY);
  test_assert(fd >= 0);

  char buf[128];
  char* current;
  int bytes;
  while ((bytes = syscall(SYS_getdents64, fd, &buf, sizeof(buf)))) {
    current = buf;
    while (current != buf + bytes) {
      struct dirent64* ent = (struct dirent64*)current;
      char* end;
      int fd = strtol(ent->d_name, &end, 10);
      if (!*end) {
        test_assert(fd < 20); // Other fds should be cloaked!
      }
      current += ent->d_reclen;
    }
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
