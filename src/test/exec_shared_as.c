/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static pid_t child_tid;
static char *exe;

static int do_child(__attribute__((unused)) void* p) {
  char* argv[] = { exe, NULL };
  child_tid = sys_gettid(); // Force the syscallbuf to be allocated
  execve(exe, argv, environ);
  test_assert(0 && "Failed exec!");
  return 0;
}

int main(int argc, char** argv) {
  int i;
  pid_t child;
  int status;

  test_assert(argc == 2);
  exe = argv[1];

  const size_t stack_size = 1 << 20;
  void* stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  // This test has a slight timing dependency. We want the SIGCHLD from the child process
  // exiting to be delivered exactly when the parent process resumes for the first time.
  // Our exit_fast executable makes this happen fairly reliably, but we run it a few times,
  // just to make sure.
  for (i = 0; i < 10; ++i) {
    child = clone(do_child, stack + stack_size,
                CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_VFORK |
                CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD,
            NULL, &child_tid, NULL, &child_tid);
    test_assert(child != -1);
    test_assert(child == waitpid(child, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
