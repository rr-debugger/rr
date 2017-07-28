/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#if defined(__i386__)
#define IP eip
#elif defined(__x86_64__)
#define IP rip
#else
#error unknown architecture
#endif

static void breakpoint(void) {}

int main(void) {
  pid_t child;
  int status;
  struct user_regs_struct regs;
  int pipe_fds[2];
  int mem_fd;
  char buf[1024];
  char breakpoint_instruction = 0xcc;
  char saved_byte;

  test_assert(0 == pipe(pipe_fds));

  if (0 == (child = fork())) {
    char ch;
    read(pipe_fds[0], &ch, 1);
    breakpoint();
    return 77;
  }

  sprintf(buf, "/proc/%d/mem", child);
  mem_fd = open(buf, O_RDWR);
  test_assert(mem_fd >= 0);

  test_assert(0 == ptrace(PTRACE_ATTACH, child, NULL, (void*)0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGSTOP << 8) | 0x7f));

  test_assert(1 == pread(mem_fd, &saved_byte, 1, (off_t)breakpoint));
  test_assert(1 ==
              pwrite(mem_fd, &breakpoint_instruction, 1, (off_t)breakpoint));

  test_assert(1 == write(pipe_fds[1], "x", 1));
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGTRAP << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_GETREGS, child, NULL, &regs));
  test_assert((char*)regs.IP == (char*)breakpoint + 1);

  test_assert(1 == pwrite(mem_fd, &saved_byte, 1, (off_t)breakpoint));
  --regs.IP;
  test_assert(0 == ptrace(PTRACE_SETREGS, child, NULL, &regs));
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)0));

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status));
  test_assert(WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
