/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(int argc, char** argv, char** envp) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = SIG_IGN;
  sigaction(SIGTTIN, &sa, NULL);
  sigaction(SIGTTOU, &sa, NULL);

  if (argc >= 2 && strcmp(argv[1], "--newtty") == 0) {
    int parent_to_child[2];
    pipe(parent_to_child);
    int child_to_parent[2];
    pipe(child_to_parent);

    // To call setsid() successfully this process must not be a
    // process group leader. Create a child process, make it a process
    // group leader, and move our process into that process group.
    pid_t child = fork();
    if (child == 0) {
      test_assert(setpgid(0, 0) == 0);
      test_assert(write(child_to_parent[1], "x", 1) == 1);
      char ch;
      test_assert(read(parent_to_child[0], &ch, 1) == 1);
      return 0;
    }
    char ch;
    test_assert(read(child_to_parent[0], &ch, 1) == 1);
    test_assert(setpgid(getpid(), child) == 0);
    test_assert(write(parent_to_child[1], "x", 1) == 1);

    int status;
    wait(&status);
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    test_assert(setsid() >= 0);

    // Create a new terminal, make it the controlling terminal
    // for this process, and exec the rest of the command line.
    int control_fd = posix_openpt(O_RDWR);
    test_assert(control_fd >= 0);
    test_assert(grantpt(control_fd) == 0);
    test_assert(unlockpt(control_fd) == 0);

    char buf[PATH_MAX];
    ptsname_r(control_fd, buf, sizeof(buf));
    int term_fd = open(buf, O_RDWR);
    test_assert(term_fd >= 0);

    test_assert(dup2(term_fd, STDIN_FILENO) == STDIN_FILENO);

    execve(argv[2], argv + 2, envp);
    return 65;
  }

  if (argc >= 2 && strcmp(argv[1], "--newpgrp") == 0) {
    // Make this process the foreground process for our terminal
    // and exec the rest of the command line.
    test_assert(setpgrp() >= 0);
    test_assert(tcsetpgrp(STDIN_FILENO, getpid()) >= 0);
    execve(argv[2], argv + 2, envp);
    return 66;
  }

  // Check that we are the foreground process for our terminal.
  int pgrp = tcgetpgrp(STDIN_FILENO);
  if (pgrp != getpid()) {
    atomic_printf("tcgetpgrp() == %d, expected %d\n", pgrp, getpid());
    return 67;
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
