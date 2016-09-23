/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"
#include <ctype.h>

#define RR_PAGE_ADDR 0x70000000

static char* trim_leading_blanks(char* str) {
  char* trimmed = str;
  while (isblank(*trimmed)) {
    ++trimmed;
  }
  return trimmed;
}

long checked_ptrace(enum __ptrace_request request, pid_t pid, void* addr,
                    void* data) {
  long ret = ptrace(request, pid, addr, data);
  assert(ret != -1);
  return ret;
}

extern char syscall_addr;
static __attribute__((noinline, used)) void my_syscall(void) {
#if defined(__i386)
  __asm__ __volatile__("syscall_addr: int $0x80\n\t");
#elif defined(__x86_64__)
  __asm__ __volatile__("syscall_addr: syscall\n\t");
#endif
}

void munmap_remote(pid_t child, uintptr_t start, size_t size) {
  struct user_regs_struct regs;
  struct iovec iov;
  int status;
  pid_t wret;
  iov.iov_base = &regs;
  iov.iov_len = sizeof(regs);
  checked_ptrace(PTRACE_GETREGSET, child, (void*)NT_PRSTATUS, &iov);
#ifdef __i386
  regs.eip = (uintptr_t)&syscall_addr;
  regs.eax = __NR_munmap;
  regs.ebx = start;
  regs.ecx = size;
#else
  regs.rip = (uintptr_t)&syscall_addr;
  regs.rax = __NR_munmap;
  regs.rdi = start;
  regs.rsi = size;
  regs.rdx = 0;
  regs.r10 = 0;
  regs.r8 = 0;
  regs.r9 = 0;
#endif
  checked_ptrace(PTRACE_SETREGSET, child, (void*)NT_PRSTATUS, &iov);
  // Execute the syscall
  checked_ptrace(PTRACE_SYSCALL, child, 0, 0);
  // Wait until entry trap
  wret = waitpid(child, &status, __WALL | WSTOPPED);
  assert(wret = child);
  assert(WSTOPSIG(status) == (SIGTRAP | 0x80));

  checked_ptrace(PTRACE_SYSCALL, child, 0, 0);
  // Wait until exit trap
  wret = waitpid(child, &status, __WALL | WSTOPPED);
  assert(wret = child);
  assert(WSTOPSIG(status) == (SIGTRAP | 0x80));
  // Verify that the syscall didn't fail
  checked_ptrace(PTRACE_GETREGSET, child, (void*)NT_PRSTATUS, &iov);
#ifdef __i386
  assert(regs.eax != -1);
#else
  assert(regs.rax != (uintptr_t)-1);
#endif
}

#ifdef __i386
static const uint8_t syscall_instr[] = { 0xcd, 0x80 };
#else
static const uint8_t syscall_instr[] = { 0x0f, 0x05, 0x00, 0x00 };
#endif

static __attribute__((noinline)) void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

int main(void) {
  pid_t child;
  if (0 == (child = fork())) {
    raise(SIGSTOP);
    char* args[] = { "/proc/self/exe", NULL };
    execve("/proc/self/exe", args, environ);
  }

  // Wait until stopped
  int status;
  pid_t wret = waitpid(child, &status, __WALL | WSTOPPED);
  assert(wret == child);
  assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  // Now PTRACE_SEIZE the child
  checked_ptrace(PTRACE_SEIZE, child, NULL,
                 (void*)(PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC));

  // That caused another stop
  wret = waitpid(child, &status, __WALL | WSTOPPED);
  assert(wret = child);

  // Continue until the exec
  checked_ptrace(PTRACE_CONT, child, 0, 0);
  // This should be the exec stop
  wret = waitpid(child, &status, __WALL | WSTOPPED);
  assert(wret = child);
  assert(status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8)));

  // Ok, now start unmapping the remote mappings
  char path[200];
  snprintf(path, 200, "/proc/%d/maps", child);
  FILE* maps_file = fopen(path, "r");

  while (!feof(maps_file)) {
    char line[PATH_MAX * 2];
    if (!fgets(line, sizeof(line), maps_file)) {
      break;
    }

    uint64_t start, end, offset, inode;
    int dev_major, dev_minor;
    char flags[32];
    int chars_scanned;
    int nparsed = sscanf(line, "%" SCNx64 "-%" SCNx64 " %31s %" SCNx64
                               " %x:%x %" SCNu64 " %n",
                         &start, &end, flags, &offset, &dev_major, &dev_minor,
                         &inode, &chars_scanned);
    assert(8 /*number of info fields*/ == nparsed ||
           7 /*num fields if name is blank*/ == nparsed);

    // trim trailing newline, if any
    int last_char = strlen(line) - 1;
    if (line[last_char] == '\n') {
      line[last_char] = 0;
    }
    char* name = trim_leading_blanks(line + chars_scanned);

    if ((start <= (uintptr_t)&syscall_addr && (uintptr_t)&syscall_addr < end) ||
        start == RR_PAGE_ADDR || strcmp(name, "[vsyscall]") == 0)
      continue;

    munmap_remote(child, start, end - start);
  }
  breakpoint();

  atomic_printf("EXIT-SUCCESS");
  return 0;
}
