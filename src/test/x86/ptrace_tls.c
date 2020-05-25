/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include <asm/ldt.h>
#include <asm/prctl.h>
#include <linux/unistd.h>
#include <sys/prctl.h>

#ifndef PTRACE_GET_THREAD_AREA
#define PTRACE_GET_THREAD_AREA 25
#endif

#ifndef PTRACE_SET_THREAD_AREA
#define PTRACE_SET_THREAD_AREA 26
#endif

#ifndef PTRACE_ARCH_PRCTL
#define PTRACE_ARCH_PRCTL 30
#endif

int main(void) {

  pid_t child;
  int status;
  size_t page_size = sysconf(_SC_PAGESIZE);

  uint8_t pattern = 0xab;
  uint8_t pattern_verify = 0;

#if defined(__i386__)

  // The minimum usable TLS descriptor varies between kernel configurations
  // Allocate the next usable one in the parent, which should then also be
  // available in the child.
  struct user_desc parent_desc;
  parent_desc.entry_number = -1;
  parent_desc.base_addr = ((uintptr_t)&main & ~(page_size - 1));
  parent_desc.limit = 1;
  parent_desc.seg_32bit = 1;
  parent_desc.contents = 0;
  parent_desc.read_exec_only = 0;
  parent_desc.limit_in_pages = 1;
  parent_desc.seg_not_present = 0;
  parent_desc.useable = 1;

  test_assert(0 == syscall(SYS_set_thread_area, &parent_desc));
#endif

  if (0 == (child = fork())) {
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    raise(SIGSTOP);
#if defined(__i386__)
    struct user_desc desc;
    memset(&desc, 0, sizeof(struct user_desc));
    desc.entry_number = parent_desc.entry_number;
    test_assert(0 == syscall(SYS_get_thread_area, &desc));
    test_assert(desc.base_addr == ((uintptr_t)&main & ~(page_size - 1)));
    test_assert(desc.limit == 1);
    desc.limit = 2;
    test_assert(0 == syscall(SYS_set_thread_area, &desc));
    desc.limit = 0;
    test_assert(0 == syscall(SYS_get_thread_area, &desc));
    test_assert(desc.limit == 2);
    raise(SIGSTOP);
    asm("mov %1, %%fs\n\t"
        "mov %%fs:0, %0"
        : "=r"(pattern_verify)
        : "r"(desc.entry_number << 3 | 3));
    test_assert(pattern_verify == pattern);
    raise(SIGSTOP);

#elif defined(__x86_64__)
    uintptr_t gs_base, fs_base;
    test_assert(0 == syscall(SYS_arch_prctl, ARCH_GET_GS, &gs_base));
    test_assert(0 == syscall(SYS_arch_prctl, ARCH_GET_FS, &fs_base));
    test_assert(0 == syscall(SYS_arch_prctl, ARCH_SET_GS, gs_base + 0x10));

    pid_t pid = getpid();
    // Avoid entering libc for anything too complex, until we're back from the
    // SIGSTOP.
    // The TLS is invalid, so anything that looks at it may cause strange
    // behavior
    int err = syscall(SYS_arch_prctl, ARCH_SET_FS, fs_base - 0x10);
    syscall(SYS_tgkill, pid, sys_gettid(), SIGSTOP);
    test_assert(err == 0);

    uintptr_t new_gs_base, new_fs_base;
    test_assert(0 == syscall(SYS_arch_prctl, ARCH_GET_GS, &new_gs_base));
    test_assert(0 == syscall(SYS_arch_prctl, ARCH_GET_FS, &new_fs_base));
    test_assert(gs_base == new_gs_base);
    test_assert(fs_base == new_fs_base);
    raise(SIGSTOP);

    asm("mov %%gs:0, %0" : "=r"(pattern_verify) :);
    test_assert(pattern_verify == pattern);
    raise(SIGSTOP);
#else
#error Test any architecture specific TLS options here
#endif
    return 0;
  }

  /* Wait until the tracee stops */
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

#if defined(__i386__)
  test_assert(0 == ptrace(PTRACE_SET_THREAD_AREA, child,
                          parent_desc.entry_number, &parent_desc));

  /* Restart the tracee, which will look at and modify this */
  ptrace(PTRACE_CONT, child, 0, 0);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  test_assert(0 == ptrace(PTRACE_GET_THREAD_AREA, child,
                          parent_desc.entry_number, &parent_desc));
  test_assert(parent_desc.limit == 2);

  /* Next we're going to verify that these are actually reflected in to the LDT
     during execution */
  parent_desc.base_addr = (uintptr_t)&pattern;
  test_assert(0 == ptrace(PTRACE_SET_THREAD_AREA, child,
                          parent_desc.entry_number, &parent_desc));

  /* Restart the tracee */
  ptrace(PTRACE_CONT, child, 0, 0);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

#elif defined(__x86_64__)
  (void)page_size;
  uintptr_t gs_base, fs_base;
  ptrace(PTRACE_ARCH_PRCTL, child, &gs_base, ARCH_GET_GS);
  ptrace(PTRACE_ARCH_PRCTL, child, &fs_base, ARCH_GET_FS);

  /* Restart the tracee, which will modify these */
  ptrace(PTRACE_CONT, child, 0, 0);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  uintptr_t new_gs_base, new_fs_base;
  ptrace(PTRACE_ARCH_PRCTL, child, &new_gs_base, ARCH_GET_GS);
  ptrace(PTRACE_ARCH_PRCTL, child, &new_fs_base, ARCH_GET_FS);
  test_assert(new_gs_base == gs_base + 0x10);
  test_assert(new_fs_base == fs_base - 0x10);

  /* Reset these. The tracee will make sure that it can see them */
  ptrace(PTRACE_ARCH_PRCTL, child, fs_base, ARCH_SET_FS);
  ptrace(PTRACE_ARCH_PRCTL, child, gs_base, ARCH_SET_GS);

  /* Restart the tracee */
  ptrace(PTRACE_CONT, child, 0, 0);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  /* Lastly, we check that these registers actually get reflected into the
     tracee */
  ptrace(PTRACE_ARCH_PRCTL, child, &pattern, ARCH_SET_GS);

  /* Restart the tracee */
  ptrace(PTRACE_CONT, child, 0, 0);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

#else
#error Test any architecture specific TLS options here
#endif

  ptrace(PTRACE_DETACH, child, 0, 0);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
