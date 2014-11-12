/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "kernel_metadata.h"

#include <assert.h>
#include <sys/ptrace.h>
#include <syscall.h>

#include "kernel_abi.h"
#include "kernel_supplement.h"
#include "log.h"

using namespace rr;

#include "SyscallnameArch.generated"

const char* syscall_name(int syscall, SupportedArch arch) {
  RR_ARCH_FUNCTION(syscallname_arch, arch, syscall)
}

const char* ptrace_event_name(int event) {
  switch (event) {
#define CASE(_id)                                                              \
  case PTRACE_EVENT_##_id:                                                     \
    return #_id
    CASE(FORK);
    CASE(VFORK);
    CASE(CLONE);
    CASE(EXEC);
    CASE(VFORK_DONE);
    CASE(EXIT);
/* XXX Ubuntu 12.04 defines a "PTRACE_EVENT_STOP", but that
 * has the same value as the newer EVENT_SECCOMP, so we'll
 * ignore STOP. */
#ifdef PTRACE_EVENT_SECCOMP_OBSOLETE
    CASE(SECCOMP_OBSOLETE);
#else
    CASE(SECCOMP);
#endif
    CASE(STOP);
    default:
      return "???EVENT";
#undef CASE
  }
}

const char* ptrace_req_name(int request) {
#define CASE(_id)                                                              \
  case PTRACE_##_id:                                                           \
    return #_id
  switch (int(request)) {
    CASE(TRACEME);
    CASE(PEEKTEXT);
    CASE(PEEKDATA);
    CASE(PEEKUSER);
    CASE(POKETEXT);
    CASE(POKEDATA);
    CASE(POKEUSER);
    CASE(CONT);
    CASE(KILL);
    CASE(SINGLESTEP);
    CASE(GETREGS);
    CASE(SETREGS);
    CASE(GETFPREGS);
    CASE(SETFPREGS);
    CASE(ATTACH);
    CASE(DETACH);
    CASE(GETFPXREGS);
    CASE(SETFPXREGS);
    CASE(SYSCALL);
    CASE(SETOPTIONS);
    CASE(GETEVENTMSG);
    CASE(GETSIGINFO);
    CASE(SETSIGINFO);
    CASE(GETREGSET);
    CASE(SETREGSET);
    CASE(SEIZE);
    CASE(INTERRUPT);
    CASE(LISTEN);
    // These aren't part of the official ptrace-request enum.
    CASE(SYSEMU);
    CASE(SYSEMU_SINGLESTEP);
#undef CASE
    default:
      return "???REQ";
  }
}

const char* signalname(int sig) {
  /* strsignal() would be nice to use here, but it provides TMI. */
  if (SIGRTMIN <= sig && sig <= SIGRTMAX) {
    static __thread char buf[] = "SIGRT00000000";
    snprintf(buf, sizeof(buf) - 1, "SIGRT%d", sig - SIGRTMIN);
    return buf;
  }

  switch (sig) {
#define CASE(_id)                                                              \
  case _id:                                                                    \
    return #_id
    CASE(SIGHUP);
    CASE(SIGINT);
    CASE(SIGQUIT);
    CASE(SIGILL);
    CASE(SIGTRAP);
    CASE(SIGABRT); /*CASE(SIGIOT);*/
    CASE(SIGBUS);
    CASE(SIGFPE);
    CASE(SIGKILL);
    CASE(SIGUSR1);
    CASE(SIGSEGV);
    CASE(SIGUSR2);
    CASE(SIGPIPE);
    CASE(SIGALRM);
    CASE(SIGTERM);
    CASE(SIGSTKFLT); /*CASE(SIGCLD);*/
    CASE(SIGCHLD);
    CASE(SIGCONT);
    CASE(SIGSTOP);
    CASE(SIGTSTP);
    CASE(SIGTTIN);
    CASE(SIGTTOU);
    CASE(SIGURG);
    CASE(SIGXCPU);
    CASE(SIGXFSZ);
    CASE(SIGVTALRM);
    CASE(SIGPROF);
    CASE(SIGWINCH); /*CASE(SIGPOLL);*/
    CASE(SIGIO);
    CASE(SIGPWR);
    CASE(SIGSYS);
#undef CASE

    default:
      return "???signal";
  }
}

#include "IsAlwaysEmulatedSyscall.generated"

bool is_always_emulated_syscall(int syscall, SupportedArch arch) {
  RR_ARCH_FUNCTION(is_always_emulated_syscall_arch, arch, syscall);
}
