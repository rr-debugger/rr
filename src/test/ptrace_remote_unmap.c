/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include <ctype.h>

#define RR_PAGE_ADDR 0x70000000

long checked_ptrace(enum __ptrace_request request, pid_t pid, void* addr,
                    void* data) {
  long ret = ptrace(request, pid, addr, data);
  test_assert(ret != -1);
  return ret;
}

extern char syscall_addr;
uintptr_t child_syscall_addr;
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
  regs.eip = child_syscall_addr;
  regs.eax = __NR_munmap;
  regs.ebx = start;
  regs.ecx = size;
#else
  regs.rip = child_syscall_addr;
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
  test_assert(wret == child);
  test_assert(WSTOPSIG(status) == (SIGTRAP | 0x80));

  checked_ptrace(PTRACE_SYSCALL, child, 0, 0);
  // Wait until exit trap
  wret = waitpid(child, &status, __WALL | WSTOPPED);
  test_assert(wret == child);
  test_assert(WSTOPSIG(status) == (SIGTRAP | 0x80));
  // Verify that the syscall didn't fail
  checked_ptrace(PTRACE_GETREGSET, child, (void*)NT_PRSTATUS, &iov);
#ifdef __i386
  test_assert(regs.eax != -1);
#else
  test_assert(regs.rax != (uintptr_t)-1);
#endif
}

static void remote_unmap_callback(uint64_t child, char* name,
                                  map_properties_t* props) {
  if ((props->start <= child_syscall_addr && child_syscall_addr < props->end) ||
      props->start == RR_PAGE_ADDR || strcmp(name, "[vsyscall]") == 0) {
    return;
  }

  munmap_remote(child, props->start, props->end - props->start);
}

static __attribute__((noinline)) void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

char exe_path[200];
uintptr_t my_start = 0, their_start = 0;
static void find_exe_mapping_start(uint64_t which, char* name,
                                   map_properties_t* props) {
  // Find an executable mapping with the given name
  uintptr_t* start = (which ? &their_start : &my_start);
  if (*start == 0 && memcmp(props->flags, "r-xp", 4) == 0 &&
      strcmp(exe_path, name) == 0) {
    *start = props->start;
  }
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
  test_assert(wret == child);
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  // Now PTRACE_SEIZE the child
  checked_ptrace(PTRACE_SEIZE, child, NULL,
                 (void*)(PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC));

  // That caused another stop
  wret = waitpid(child, &status, __WALL | WSTOPPED);
  test_assert(wret == child);

  // Continue until the exec
  checked_ptrace(PTRACE_CONT, child, 0, 0);
  // This should be the exec stop
  wret = waitpid(child, &status, __WALL | WSTOPPED);
  test_assert(wret == child);
  test_assert(status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8)));

  // On kernels with aggressive ASLR, the executable mapping may
  // not be in the same place that it is now. Find it again.
  ssize_t path_size = readlink("/proc/self/exe", exe_path, 200);
  test_assert(path_size > 0);

  // First find the correct mapping in our own address space.
  FILE* own_maps = fopen("/proc/self/maps", "r");
  iterate_maps(0, find_exe_mapping_start, own_maps);
  fclose(own_maps);

  // Now find the same mapping in the new process
  char path[200];
  snprintf(path, 200, "/proc/%d/maps", child);
  FILE* maps_file = fopen(path, "r");
  iterate_maps(1, find_exe_mapping_start, maps_file);
  fclose(maps_file);

  // Adjust the syscall address by the slide
  child_syscall_addr = (uintptr_t)&syscall_addr + (their_start - my_start);

  // Ok, now start unmapping the remote mappings
  maps_file = fopen(path, "r");

  iterate_maps(child, remote_unmap_callback, maps_file);
  breakpoint();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
