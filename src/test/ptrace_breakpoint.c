/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include "ptrace_util.h"

static void breakpoint(void) {}

#if defined(__i386__) || defined(__x86_64__)
char breakpoint_instruction[] = { 0xcc };
int ip_after_breakpoint = 1;
#elif defined(__aarch64__)
char breakpoint_instruction[] = { 0x0, 0x0, 0x20, 0xd4 };
int ip_after_breakpoint = 0;
#else
#error Unknown architecture
#endif

int main(void) {
  pid_t child;
  int status;
  struct user_regs_struct regs;
  int pipe_fds[2];
  int mem_fd;
  char buf[1024];
  char saved_bytes[sizeof(breakpoint_instruction)];
  ssize_t bkpt_size = sizeof(breakpoint_instruction);

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

  test_assert(bkpt_size ==
    pread(mem_fd, saved_bytes, bkpt_size, (off_t)breakpoint));
  test_assert(bkpt_size ==
    pwrite(mem_fd, breakpoint_instruction, bkpt_size, (off_t)breakpoint));

  test_assert(1 == write(pipe_fds[1], "x", 1));
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGTRAP << 8) | 0x7f));
  ptrace_getregs(child, &regs);
  test_assert((char*)regs.IP == (char*)breakpoint + ip_after_breakpoint ? bkpt_size : 0);

  test_assert(bkpt_size == pwrite(mem_fd, saved_bytes, bkpt_size, (off_t)breakpoint));
  if (ip_after_breakpoint) {
    regs.IP -= bkpt_size;
  }
  ptrace_setregs(child, &regs);
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)0));

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status));
  test_assert(WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
