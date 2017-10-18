/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define SYS_rrcall_init_buffers 443

static int count_SIGSYS = 0;

static int pipe_fds[2];

static void handler(int sig, siginfo_t* si, void* p) {
  ucontext_t* ctx = p;
/* some versions of system headers don't define si_arch, si_call_addr or
 * si_syscall. Just skip tests on those systems.
 */
#ifdef __i386__
  int syscallno = ctx->uc_mcontext.gregs[REG_EAX];
#elif defined(__x86_64__)
  int syscallno = ctx->uc_mcontext.gregs[REG_RAX];
#else
#error define architecture here
#endif

#ifdef si_arch
#ifdef __i386__
  test_assert(si->si_arch == AUDIT_ARCH_I386);
#elif defined(__x86_64__)
  test_assert(si->si_arch == AUDIT_ARCH_X86_64);
#endif
#endif
  test_assert(syscallno == SYS_geteuid || syscallno == SYS_open);

  test_assert(sig == SIGSYS);
  test_assert(si->si_signo == SIGSYS);
  test_assert(si->si_errno == 0);
  test_assert(si->si_code == 1 /* SYS_SECCOMP */);
#ifdef si_call_addr
#ifdef __i386__
  test_assert((intptr_t)si->si_call_addr == ctx->uc_mcontext.gregs[REG_EIP]);
#elif defined(__x86_64__)
  test_assert((intptr_t)si->si_call_addr == ctx->uc_mcontext.gregs[REG_RIP]);
#else
#error define architecture here
#endif
#endif

  if (syscallno == SYS_geteuid) {
#ifdef __i386__
    ctx->uc_mcontext.gregs[REG_EAX] = 42;
#elif defined(__x86_64__)
    ctx->uc_mcontext.gregs[REG_RAX] = 42;
#else
#error define architecture here
#endif
  }

#ifdef si_syscall
  test_assert(si->si_syscall == syscallno);
#endif
  ++count_SIGSYS;
}

static void install_filter(void) {
  struct sock_filter filter[] = {
    /* Load system call number from 'seccomp_data' buffer into
       accumulator */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    /* Jump forward 1 instruction if system call number
       is not SYS_pipe */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_pipe, 0, 1),
    /* Error out with ESRCH */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (ESRCH & SECCOMP_RET_DATA)),
    /* Jump forward 1 instruction if system call number
       is not SYS_geteuid */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_geteuid, 0, 1),
    /* Trigger SIGSYS */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
    /* Jump forward 1 instruction if system call number
       is not SYS_open */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_open, 0, 1),
    /* Trigger SIGSYS */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
    /* Jump forward 1 instruction if system call number
       is not SYS_rrcall_init_buffers */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_rrcall_init_buffers, 0, 1),
    /* Trigger SIGSYS */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
    /* Jump forward 1 instruction if system call number
       is not SYS_ioctl */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_ioctl, 0, 1),
    /* Trigger SIGSYS */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
    /* Jump forward 1 instruction if system call number
       is not SYS_sched_yield */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_sched_yield, 0, 1),
    /* Kill process */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
    /* Destination of system call number mismatch: allow other
       system calls */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
  };
  struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
    .filter = filter,
  };
  int ret;

  ret = syscall(RR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
  if (ret == -1 && errno == ENOSYS) {
    ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
  }
  test_assert(ret == 0);
}

static void* waiting_thread(__attribute__((unused)) void* p) {
  char buf;
  test_assert(1 == read(pipe_fds[0], &buf, 1));
  /* Check this thread wasn't affected by the SET_SECCOMP */
  test_assert(0 == prctl(PR_GET_SECCOMP));
  return NULL;
}

static void* run_thread(__attribute__((unused)) void* p) {
  atomic_printf("EXIT-");
  return NULL;
}

int main(void) {
  struct sigaction sa;
  pthread_t thread;
  pthread_t w_thread;
  char ch;

  test_assert(0 == pipe(pipe_fds));

  sa.sa_sigaction = handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  sigaction(SIGSYS, &sa, NULL);

  pthread_create(&w_thread, NULL, waiting_thread, NULL);

  /* Prepare syscallbuf patch path. Need to do this after
     pthread_create since when we have more than one
     thread we take a different syscall path... */
  open("/dev/null", O_RDONLY);

  test_assert(0 == prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
  test_assert(1 == prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0));
  install_filter();
  test_assert(2 == prctl(PR_GET_SECCOMP));

  test_assert(1 == write(pipe_fds[1], "c", 1));
  pthread_join(w_thread, NULL);

  test_assert(-1 == syscall(SYS_pipe, pipe_fds));
  test_assert(ESRCH == errno);

  /* Spawning a thread will execute an rrcall_init_buffers syscall,
     which our filter tries to block but shouldn't be able to. */
  pthread_create(&thread, NULL, run_thread, NULL);
  pthread_join(thread, NULL);

  /* Check that the ioctls used by syscallbuf aren't blocked */
  test_assert(1 == write(pipe_fds[1], "c", 1));
  test_assert(1 == read(pipe_fds[0], &ch, 1));
  test_assert(1 == write(pipe_fds[1], "c", 1));
  test_assert(1 == read(pipe_fds[0], &ch, 1));

  test_assert(syscall(SYS_geteuid) == 42);
  /* Use syscall directly since glibc 2.26 uses SYS_openat to implement open. */
  syscall(SYS_open, "/dev/null", O_RDONLY);
  test_assert(count_SIGSYS == 2);

  atomic_puts("SUCCESS");

  sched_yield();
  abort();
  return 0;
}
