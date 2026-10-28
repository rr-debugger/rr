/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A ptracer with PTRACE_O_TRACECLONE and PTRACE_O_TRACEEXEC traces a child
   in which one thread execs while another one sleeps: first a non-leader
   thread, then the leader. The tracer gets the exec stop and continues until
   the new image exits. */

static char exe[4096];
static int go_fds[2];

static void do_exec(void) {
  char* argv[] = { exe, "exec'd", NULL };
  execve(exe, argv, environ);
  test_assert(0 && "Failed exec!");
}

static void* sleeper(__attribute__((unused)) void* p) {
  while (1) {
    pause();
  }
  return NULL;
}

static void* exec_thread(__attribute__((unused)) void* p) {
  do_exec();
  return NULL;
}

static void run_child(int leader_execs) {
  pthread_t thread;
  char ch;
  test_assert(1 == read(go_fds[0], &ch, 1));
  test_assert(0 == pthread_create(&thread, NULL, sleeper, NULL));
  if (leader_execs) {
    do_exec();
  }
  test_assert(0 == pthread_create(&thread, NULL, exec_thread, NULL));
  sleeper(NULL);
}

static void run_test(int leader_execs) {
  int exec_stops = 0;
  int status;
  pid_t child;

  test_assert(0 == pipe(go_fds));
  child = fork();
  if (!child) {
    run_child(leader_execs);
  }
  test_assert(child > 0);
  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL,
                          (void*)(uintptr_t)(PTRACE_O_TRACECLONE |
                                             PTRACE_O_TRACEEXEC)));
  test_assert(1 == write(go_fds[1], "x", 1));
  test_assert(0 == close(go_fds[0]));
  test_assert(0 == close(go_fds[1]));

  while (1) {
    int sig = 0;
    pid_t w = waitpid(-1, &status, __WALL);
    if (w < 0) {
      test_assert(errno == ECHILD);
      break;
    }
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      if (w == child) {
        test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
      }
      continue;
    }
    test_assert(WIFSTOPPED(status));
    if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
      test_assert(w == child);
      ++exec_stops;
    } else if (!(status >> 16) && WSTOPSIG(status) != SIGSTOP &&
               WSTOPSIG(status) != SIGTRAP) {
      sig = WSTOPSIG(status);
    }
    /* The task may have been killed since it stopped. */
    ptrace(PTRACE_CONT, w, NULL, (void*)(uintptr_t)sig);
  }
  test_assert(exec_stops == 1);
}

int main(int argc, char** argv) {
  ssize_t len;

  if (argc == 2) {
    test_assert(!strcmp(argv[1], "exec'd"));
    return 77;
  }
  len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
  test_assert(len > 0);
  exe[len] = 0;

  run_test(0);
  run_test(1);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
