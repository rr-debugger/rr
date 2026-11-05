/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A thread wakes the other threads, which are blocked in read(), and
   execs. The exec has to wait for the other threads to exit, and kills them
   while they may be returning from their reads, so rr must handle their
   exits while the exec is in progress. The race it tests only happens in
   some recordings. */

#define NUM_ROUNDS 3
#define NUM_READERS 4

static void* reader(void* p) {
  int fd = (int)(intptr_t)p;
  char ch;
  test_assert(1 == read(fd, &ch, 1));
  while (1) {
    pause();
  }
  return NULL;
}

static void* wake_readers_and_exec(void* p) {
  int fd = (int)(intptr_t)p;
  char exe[4096];
  char* argv[] = { exe, "exec'd", NULL };
  ssize_t len;
  int i;

  len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
  test_assert(len > 0);
  exe[len] = 0;
  for (i = 0; i < NUM_READERS; ++i) {
    test_assert(1 == write(fd, "x", 1));
  }
  execve(exe, argv, environ);
  test_assert(0 && "Failed exec!");
  return NULL;
}

int main(int argc, char** argv) {
  int i;

  if (argc == 2) {
    test_assert(!strcmp(argv[1], "exec'd"));
    return 77;
  }

  for (i = 0; i < NUM_ROUNDS; ++i) {
    int status;
    pid_t child = fork();
    test_assert(child >= 0);
    if (!child) {
      pthread_t thread;
      int fds[2];
      int j;
      test_assert(0 == pipe(fds));
      /* The main thread is the last reader. */
      for (j = 0; j < NUM_READERS - 1; ++j) {
        test_assert(0 == pthread_create(&thread, NULL, reader,
                                        (void*)(intptr_t)fds[0]));
      }
      test_assert(0 == pthread_create(&thread, NULL, wake_readers_and_exec,
                                      (void*)(intptr_t)fds[1]));
      reader((void*)(intptr_t)fds[0]);
    }
    test_assert(child == waitpid(child, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
