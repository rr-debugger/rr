/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* When a process that shares an address space with others (CLONE_VM) execs,
   rr unmaps its syscall buffer and scratch memory from that address space,
   with remote syscalls in the next task there that it processes. Here that
   task is stopped at the seccomp stop of a syscall: rr reports the syscall's
   entry to our ptracer there, and the ptracer resumes the tracee only after
   the tracee's CLONE_VM child has exec'd.
   To get back to the seccomp stop after the remote syscalls, rr executes the
   syscall instruction again. On x86-64 that sets rcx and r11, and the
   syscall's exit must still look the same in recording and replay. */

static int to_child[2];
static int from_child[2];

static int clone_child(__attribute__((unused)) void* arg) {
  char fd[32];
  char ch;
  char* argv[] = { "/proc/self/exe", fd, NULL };
  /* Wait until our parent is stopped at the syscall entry. */
  if (1 != read(to_child[0], &ch, 1)) {
    return 1;
  }
  sprintf(fd, "%d", from_child[1]);
  execve(argv[0], argv, environ);
  return 1;
}

static int tracee(void) {
  size_t stack_size = 1024 * 1024;
  char* stack = (char*)mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  pid_t pid;
  int status;
  long sid;

  test_assert(stack != MAP_FAILED);
  test_assert(0 == ptrace(PTRACE_TRACEME, 0, 0, 0));
  test_assert(0 == raise(SIGSTOP));

  pid = clone(clone_child, stack + stack_size, CLONE_VM | SIGCHLD, NULL);
  test_assert(pid > 0);
  sid = unbufferable_syscall(SYS_getsid, 0, 0, 0);
  test_assert(sid == getsid(0));
  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  return 0;
}

int main(int argc, char** argv) {
  pid_t child;
  int status;
  char ch;
  struct user_regs_struct regs;

  if (argc == 2) {
    /* The exec'd clone child: tell the ptracer that the exec is done. */
    return 1 == write(atoi(argv[1]), "y", 1) ? 0 : 1;
  }

  test_assert(0 == pipe(to_child));
  test_assert(0 == pipe(from_child));

  child = fork();
  if (!child) {
    return tracee();
  }

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  test_assert(0 == ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD));

  /* Run to the entry of the tracee's getsid(). */
  while (1) {
    test_assert(0 == ptrace(PTRACE_SYSCALL, child, 0, 0));
    test_assert(child == waitpid(child, &status, 0));
    test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80));
    test_assert(0 == ptrace(PTRACE_GETREGS, child, 0, &regs));
#ifdef __x86_64__
    if (regs.orig_rax == SYS_getsid) {
#else
    if (regs.orig_eax == SYS_getsid) {
#endif
      break;
    }
    /* Skip the syscall's exit. */
    test_assert(0 == ptrace(PTRACE_SYSCALL, child, 0, 0));
    test_assert(child == waitpid(child, &status, 0));
    test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80));
  }

  /* Let the clone child exec while the tracee is stopped there. */
  test_assert(1 == write(to_child[1], "x", 1));
  test_assert(1 == read(from_child[0], &ch, 1));

  /* Run the tracee to its exit, passing on signals (SIGCHLD). */
  test_assert(0 == ptrace(PTRACE_CONT, child, 0, 0));
  while (1) {
    test_assert(child == waitpid(child, &status, 0));
    if (!WIFSTOPPED(status)) {
      break;
    }
    test_assert(0 ==
                ptrace(PTRACE_CONT, child, 0, (void*)(long)WSTOPSIG(status)));
  }
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
