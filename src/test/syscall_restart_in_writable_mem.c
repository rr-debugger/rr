/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* The main thread does a blocking read() through a syscall instruction in
   writable memory. While it's blocked, another thread replaces the syscall
   instruction with an illegal instruction and a child process stops and
   continues us. The read() gets interrupted and the kernel restarts it
   without running a signal handler, so the main thread then gets a SIGILL
   at the syscall instruction. */

#if defined(__x86_64__)
#define ARCH_PC gregs[REG_RIP]
static const uint8_t code[] = {
  0x48, 0x89, 0xf8, /* mov %rdi,%rax */
  0x48, 0x89, 0xf7, /* mov %rsi,%rdi */
  0x48, 0x89, 0xd6, /* mov %rdx,%rsi */
  0x48, 0x89, 0xca, /* mov %rcx,%rdx */
  0x0f, 0x05,       /* syscall */
  0xc3              /* ret */
};
static const size_t syscall_offset = 12;
static const uint8_t illegal_insn[] = { 0x0f, 0x0b }; /* ud2 */
#elif defined(__i386__)
#define ARCH_PC gregs[REG_EIP]
static const uint8_t code[] = {
  0x53,                   /* push %ebx */
  0x8b, 0x44, 0x24, 0x08, /* mov 0x8(%esp),%eax */
  0x8b, 0x5c, 0x24, 0x0c, /* mov 0xc(%esp),%ebx */
  0x8b, 0x4c, 0x24, 0x10, /* mov 0x10(%esp),%ecx */
  0x8b, 0x54, 0x24, 0x14, /* mov 0x14(%esp),%edx */
  0xcd, 0x80,             /* int $0x80 */
  0x5b,                   /* pop %ebx */
  0xc3                    /* ret */
};
static const size_t syscall_offset = 17;
static const uint8_t illegal_insn[] = { 0x0f, 0x0b }; /* ud2 */
#elif defined(__aarch64__)
#define ARCH_PC pc
static const uint32_t code[] = {
  0xaa0003e8, /* mov x8, x0 */
  0xaa0103e0, /* mov x0, x1 */
  0xaa0203e1, /* mov x1, x2 */
  0xaa0303e2, /* mov x2, x3 */
  0xd4000001, /* svc #0 */
  0xd65f03c0  /* ret */
};
static const size_t syscall_offset = 16;
static const uint32_t illegal_insn[] = { 0x00000000 }; /* udf #0 */
#else
#error Unknown architecture
#endif

typedef long (*syscall_fn)(long no, long arg1, long arg2, long arg3);

static uint8_t* code_page;
static pid_t main_tid;
static int data_fds[2];
static int child_fds[2];
static int done_fds[2];
static volatile int caught_sigill;

static void handle_sigill(__attribute__((unused)) int sig,
                          __attribute__((unused)) siginfo_t* si, void* p) {
  ucontext_t* ctx = (ucontext_t*)p;
  test_assert((uintptr_t)ctx->uc_mcontext.ARCH_PC ==
              (uintptr_t)(code_page + syscall_offset));
  ctx->uc_mcontext.ARCH_PC += sizeof(illegal_insn);
  caught_sigill = 1;
}

static int main_thread_blocked_in_read(void) {
  char path[PATH_MAX];
  char buf[1024];
  char* p;
  long nr;
  unsigned long arg1;
  int fd;
  ssize_t len;

  sprintf(path, "/proc/self/task/%d/stat", main_tid);
  fd = open(path, O_RDONLY);
  test_assert(fd >= 0);
  len = read(fd, buf, sizeof(buf) - 1);
  test_assert(len > 0);
  buf[len] = 0;
  test_assert(0 == close(fd));
  p = strrchr(buf, ')');
  test_assert(p != NULL);
  if (p[2] != 'S') {
    return 0;
  }

  sprintf(path, "/proc/self/task/%d/syscall", main_tid);
  fd = open(path, O_RDONLY);
  test_assert(fd >= 0);
  len = read(fd, buf, sizeof(buf) - 1);
  test_assert(len > 0);
  buf[len] = 0;
  test_assert(0 == close(fd));
  return sscanf(buf, "%ld 0x%lx", &nr, &arg1) == 2 && nr == SYS_read &&
         arg1 == (unsigned long)data_fds[0];
}

static void* do_thread(__attribute__((unused)) void* p) {
  sigset_t set;
  char ch;

  sigemptyset(&set);
  sigaddset(&set, SIGCONT);
  sigaddset(&set, SIGCHLD);
  test_assert(0 == pthread_sigmask(SIG_UNBLOCK, &set, NULL));

  while (!main_thread_blocked_in_read()) {
    sched_yield();
  }
  memcpy(code_page + syscall_offset, illegal_insn, sizeof(illegal_insn));
  __builtin___clear_cache((char*)code_page, (char*)code_page + sizeof(code));
  test_assert(1 == write(child_fds[1], "x", 1));

  test_assert(1 == read(done_fds[0], &ch, 1));
  return NULL;
}

int main(void) {
  pid_t parent = getpid();
  pid_t child;
  pthread_t thread;
  struct sigaction sa;
  sigset_t set;
  int status;
  char ch;

  code_page = (uint8_t*)mmap(NULL, sysconf(_SC_PAGESIZE),
                             PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(code_page != MAP_FAILED);
  memcpy(code_page, code, sizeof(code));
  __builtin___clear_cache((char*)code_page, (char*)code_page + sizeof(code));

  test_assert(0 == pipe(data_fds));
  test_assert(0 == pipe(child_fds));
  test_assert(0 == pipe(done_fds));

  /* With the syscall buffer enabled, rr on aarch64 replaces any svc #0 it
     executes with a branch to its syscall hook. The read() below would then
     block in rr's code, and its restart would never reach this page.
     There's nothing to test in that case. */
  ((syscall_fn)code_page)(SYS_read, data_fds[0], (long)&ch, 0);
  if (memcmp(code_page + syscall_offset, (const uint8_t*)code + syscall_offset,
             sizeof(illegal_insn))) {
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  child = fork();
  if (!child) {
    test_assert(1 == read(child_fds[0], &ch, 1));
    test_assert(0 == kill(parent, SIGSTOP));
    test_assert(0 == kill(parent, SIGCONT));
    return 0;
  }

  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handle_sigill;
  sa.sa_flags = SA_SIGINFO;
  test_assert(0 == sigaction(SIGILL, &sa, NULL));

  /* Let the other thread take SIGCONT and SIGCHLD so that no signal is
     delivered to this thread after its read() is interrupted. */
  sigemptyset(&set);
  sigaddset(&set, SIGCONT);
  sigaddset(&set, SIGCHLD);
  test_assert(0 == sigprocmask(SIG_BLOCK, &set, NULL));

  main_tid = sys_gettid();
  test_assert(0 == pthread_create(&thread, NULL, do_thread, NULL));

  ((syscall_fn)code_page)(SYS_read, data_fds[0], (long)&ch, 1);
  test_assert(caught_sigill);

  test_assert(1 == write(done_fds[1], "x", 1));
  test_assert(0 == pthread_join(thread, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && 0 == WEXITSTATUS(status));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
