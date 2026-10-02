/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

static int parent_to_child_fds[2];
static int parent_to_grandchild_fds[2];
static pid_t grandchild;

static void* wait_from_other_thread(__attribute__((unused)) void* p) {
  int status;
  /* This thread is not the tracer thread. */
  test_assert(-1 ==
              waitpid(grandchild, &status, WNOHANG | __WALL | __WNOTHREAD));
  test_assert(errno == ECHILD);
  return NULL;
}

int main(void) {
  pid_t child;
  pthread_t thread;
  char ch;
  int status;
  unsigned long msg;
  siginfo_t si;
  struct rusage ru;
  struct rusage ru_unchanged;

  test_assert(0 == pipe(parent_to_child_fds));
  test_assert(0 == pipe(parent_to_grandchild_fds));

  if (0 == (child = fork())) {
    /* If the parent dies, the grandchild's read() sees EOF: nothing hangs. */
    test_assert(0 == close(parent_to_child_fds[1]));
    test_assert(0 == close(parent_to_grandchild_fds[1]));
    test_assert(1 == read(parent_to_child_fds[0], &ch, 1));
    grandchild = fork();
    if (!grandchild) {
      test_assert(1 == read(parent_to_grandchild_fds[0], &ch, 1));
      return 66;
    }
    test_assert(grandchild == waitpid(grandchild, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 66);
    return 77;
  }

  test_assert(0 ==
              ptrace(PTRACE_SEIZE, child, NULL, (void*)PTRACE_O_TRACEFORK));
  test_assert(1 == write(parent_to_child_fds[1], "p", 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((PTRACE_EVENT_FORK << 16) | (SIGTRAP << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_GETEVENTMSG, child, NULL, &msg));
  grandchild = (pid_t)msg;
  /* The grandchild is our tracee, but not our child. */
  test_assert(grandchild == waitpid(grandchild, &status, __WALL));
  test_assert(WIFSTOPPED(status) && (status >> 16) == PTRACE_EVENT_STOP);

  /* It blocks in read() without a ptrace stop: a WNOHANG wait for it
     returns 0. waitpid() and wait4() leave *status and *rusage alone,
     waitid() clears the siginfo fields it would have set. */
  test_assert(0 == ptrace(PTRACE_CONT, grandchild, NULL, (void*)0));
  status = -1;
  test_assert(0 == waitpid(grandchild, &status, WNOHANG | __WALL));
  test_assert(status == -1);
  memset(&ru, 0xff, sizeof(ru));
  memset(&ru_unchanged, 0xff, sizeof(ru_unchanged));
  test_assert(0 == wait4(grandchild, &status, WNOHANG | __WALL, &ru));
  test_assert(status == -1);
  test_assert(0 == memcmp(&ru, &ru_unchanged, sizeof(ru)));
  memset(&si, 0xff, sizeof(si));
  test_assert(0 == waitid(P_PID, grandchild, &si,
                          WSTOPPED | WEXITED | WNOHANG | __WALL));
  test_assert(si.si_signo == 0);
  test_assert(si.si_errno == 0);
  test_assert(si.si_code == 0);
  test_assert(si.si_pid == 0);
  test_assert(si.si_uid == 0);
  test_assert(si.si_status == 0);
  /* With __WNOTHREAD, only the tracer thread can wait for its tracee. */
  test_assert(0 ==
              waitpid(grandchild, &status, WNOHANG | __WALL | __WNOTHREAD));
  test_assert(0 == pthread_create(&thread, NULL, wait_from_other_thread, NULL));
  test_assert(0 == pthread_join(thread, NULL));
  /* Options the kernel rejects. */
  test_assert(-1 == waitpid(grandchild, &status, WNOHANG | WNOWAIT));
  test_assert(errno == EINVAL);
  test_assert(-1 == waitid(P_PID, grandchild, &si, WNOHANG));
  test_assert(errno == EINVAL);

  test_assert(1 == write(parent_to_grandchild_fds[1], "g", 1));
  test_assert(grandchild == waitpid(grandchild, &status, __WALL));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 66);

  /* The child observes a SIGCHLD from the grandchild's exit. */
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGCHLD);

  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
