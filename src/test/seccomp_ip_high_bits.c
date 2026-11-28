/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* read()s made from a syscall instruction that ends at an address whose
   lower 32 bits are those of the end of the rr page's untraced syscall
   instruction. rr must record them: one made directly and one that a
   signal interrupts and that then restarts. */

#if defined(__x86_64__) || defined(__aarch64__)

#define RR_PAGE_ADDR 0x70000000UL
#define HIGH_BITS 0x100000000UL

typedef long (*SyscallFunc)(long nr, long arg1, long arg2, long arg3);

#if defined(__x86_64__)
#define RR_PAGE_SYSCALL_STUB_SIZE 3
#define RR_PAGE_SYSCALL_INSTRUCTION_END 2
static const uint8_t syscall_func_code[] = {
  0x48, 0x89, 0xf8, /* mov %rdi,%rax */
  0x48, 0x89, 0xf7, /* mov %rsi,%rdi */
  0x48, 0x89, 0xd6, /* mov %rdx,%rsi */
  0x48, 0x89, 0xca, /* mov %rcx,%rdx */
  0x0f, 0x05,       /* syscall */
  0xc3              /* ret */
};
#define SYSCALL_END_OFFSET 14
#else
#define RR_PAGE_SYSCALL_STUB_SIZE 8
#define RR_PAGE_SYSCALL_INSTRUCTION_END 4
static const uint8_t syscall_func_code[] = {
  0xe8, 0x03, 0x00, 0xaa, /* mov x8, x0 */
  0xe0, 0x03, 0x01, 0xaa, /* mov x0, x1 */
  0xe1, 0x03, 0x02, 0xaa, /* mov x1, x2 */
  0xe2, 0x03, 0x03, 0xaa, /* mov x2, x3 */
  0x01, 0x00, 0x00, 0xd4, /* svc #0 */
  0xc0, 0x03, 0x5f, 0xd6  /* ret */
};
#define SYSCALL_END_OFFSET 20
#endif

/* The end of RR_PAGE_SYSCALL_UNTRACED, the third stub in the rr page */
#define UNTRACED_SYSCALL_END                                                   \
  (RR_PAGE_ADDR + 2 * RR_PAGE_SYSCALL_STUB_SIZE +                              \
   RR_PAGE_SYSCALL_INSTRUCTION_END)

static SyscallFunc syscall_func;
static int pipe_fds[2];
static pid_t main_tid;

static void handle_usr1(__attribute__((unused)) int sig) {}

static void* signal_thread(__attribute__((unused)) void* p) {
  pid_t tid = __atomic_load_n(&main_tid, __ATOMIC_SEQ_CST);
  test_assert(tid > 1);
  wait_for_task_asleep_in_syscall(tid, SYS_read, pipe_fds[0]);
  test_assert(0 == syscall(SYS_tgkill, getpid(), tid, SIGUSR1));
  test_assert(1 == write(pipe_fds[1], "y", 1));
  return NULL;
}

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  uint8_t* syscall_end = (uint8_t*)(HIGH_BITS + UNTRACED_SYSCALL_END);
  uint8_t* page = (uint8_t*)((uintptr_t)syscall_end & ~(page_size - 1));
  uint8_t* code = syscall_end - SYSCALL_END_OFFSET;
  struct sigaction sa;
  pthread_t thread;
  char ch = 0;

  /* The code can start on the page before the one the syscall ends on. */
  test_assert(page - page_size ==
              (uint8_t*)mmap(page - page_size, 2 * page_size,
                             PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0));
  memcpy(code, syscall_func_code, sizeof(syscall_func_code));
  __builtin___clear_cache((char*)code,
                          (char*)code + sizeof(syscall_func_code));
  syscall_func = (SyscallFunc)code;

  test_assert(0 == pipe(pipe_fds));
  test_assert(1 == write(pipe_fds[1], "x", 1));
  test_assert(1 == syscall_func(SYS_read, pipe_fds[0], (long)&ch, 1));
  test_assert(ch == 'x');

  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handle_usr1;
  sa.sa_flags = SA_RESTART;
  test_assert(0 == sigaction(SIGUSR1, &sa, NULL));
  __atomic_store_n(&main_tid, sys_gettid(), __ATOMIC_SEQ_CST);
  test_assert(0 == pthread_create(&thread, NULL, signal_thread, NULL));
  test_assert(1 == syscall_func(SYS_read, pipe_fds[0], (long)&ch, 1));
  test_assert(ch == 'y');
  test_assert(0 == pthread_join(thread, NULL));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#else

/* 32-bit instruction pointers have no upper half. */
int main(void) {
  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#endif
