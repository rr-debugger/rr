/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "kernel_metadata.h"

#include <errno.h>
#include <linux/shm.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <syscall.h>

#include "kernel_abi.h"
#include "kernel_supplement.h"
#include "log.h"

using namespace std;

namespace rr {

#include "SyscallnameArch.generated"

string syscall_name(int syscall, SupportedArch arch) {
  RR_ARCH_FUNCTION(syscallname_arch, arch, syscall)
}

#define CASE(_id)                                                              \
  case _id:                                                                    \
    return #_id;

string ptrace_event_name(int event) {
  switch (event) {
    CASE(PTRACE_EVENT_FORK);
    CASE(PTRACE_EVENT_VFORK);
    CASE(PTRACE_EVENT_CLONE);
    CASE(PTRACE_EVENT_EXEC);
    CASE(PTRACE_EVENT_VFORK_DONE);
    CASE(PTRACE_EVENT_EXIT);
    /* XXX Ubuntu 12.04 defines a "PTRACE_EVENT_STOP", but that
     * has the same value as the newer EVENT_SECCOMP, so we'll
     * ignore STOP. */
    CASE(PTRACE_EVENT_SECCOMP_OBSOLETE);
    CASE(PTRACE_EVENT_SECCOMP);
    CASE(PTRACE_EVENT_STOP);
    /* Special-case this so we don't need to sprintf in this common case.
     * This case is common because we often pass ptrace_event_name(event) to
     * assertions when event is 0.
     */
    case 0:
      return "PTRACE_EVENT(0)";
    default: {
      char buf[100];
      sprintf(buf, "PTRACE_EVENT(%d)", event);
      return string(buf);
    }
  }
}

string ptrace_req_name(int request) {
  switch (request) {
    CASE(PTRACE_TRACEME);
    CASE(PTRACE_PEEKTEXT);
    CASE(PTRACE_PEEKDATA);
    CASE(PTRACE_PEEKUSER);
    CASE(PTRACE_POKETEXT);
    CASE(PTRACE_POKEDATA);
    CASE(PTRACE_POKEUSER);
    CASE(PTRACE_CONT);
    CASE(PTRACE_KILL);
    CASE(PTRACE_SINGLESTEP);
    CASE(PTRACE_GETREGS);
    CASE(PTRACE_SETREGS);
    CASE(PTRACE_GETFPREGS);
    CASE(PTRACE_SETFPREGS);
    CASE(PTRACE_ATTACH);
    CASE(PTRACE_DETACH);
    CASE(PTRACE_GETFPXREGS);
    CASE(PTRACE_SETFPXREGS);
    CASE(PTRACE_SYSCALL);
    CASE(PTRACE_SETOPTIONS);
    CASE(PTRACE_GETEVENTMSG);
    CASE(PTRACE_GETSIGINFO);
    CASE(PTRACE_SETSIGINFO);
    CASE(PTRACE_GETREGSET);
    CASE(PTRACE_SETREGSET);
    CASE(PTRACE_SEIZE);
    CASE(PTRACE_INTERRUPT);
    CASE(PTRACE_LISTEN);
    // These aren't part of the official ptrace-request enum.
    CASE(PTRACE_SYSEMU);
    CASE(PTRACE_SYSEMU_SINGLESTEP);
    default: {
      char buf[100];
      sprintf(buf, "PTRACE_REQUEST(%d)", request);
      return string(buf);
    }
  }
}

string signal_name(int sig) {
  /* strsignal() would be nice to use here, but it provides TMI. */
  if (32 <= sig && sig <= 64) {
    char buf[100];
    snprintf(buf, sizeof(buf) - 1, "SIGRT%d", sig);
    return buf;
  }

  switch (sig) {
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
    /* Special-case this so we don't need to sprintf in this common case.
     * This case is common because we often pass signal_name(sig) to assertions
     * when sig is 0.
     */
    case 0:
      return "signal(0)";
    default: {
      char buf[100];
      sprintf(buf, "signal(%d)", sig);
      return string(buf);
    }
  }
}

bool is_sigreturn(int syscallno, SupportedArch arch) {
  return is_sigreturn_syscall(syscallno, arch) ||
         is_rt_sigreturn_syscall(syscallno, arch);
}

string errno_name(int err) {
  switch (err) {
    case 0:
      return "SUCCESS";
      CASE(EPERM);
      CASE(ENOENT);
      CASE(ESRCH);
      CASE(EINTR);
      CASE(EIO);
      CASE(ENXIO);
      CASE(E2BIG);
      CASE(ENOEXEC);
      CASE(EBADF);
      CASE(ECHILD);
      CASE(EAGAIN);
      CASE(ENOMEM);
      CASE(EACCES);
      CASE(EFAULT);
      CASE(ENOTBLK);
      CASE(EBUSY);
      CASE(EEXIST);
      CASE(EXDEV);
      CASE(ENODEV);
      CASE(ENOTDIR);
      CASE(EISDIR);
      CASE(EINVAL);
      CASE(ENFILE);
      CASE(EMFILE);
      CASE(ENOTTY);
      CASE(ETXTBSY);
      CASE(EFBIG);
      CASE(ENOSPC);
      CASE(ESPIPE);
      CASE(EROFS);
      CASE(EMLINK);
      CASE(EPIPE);
      CASE(EDOM);
      CASE(ERANGE);
      CASE(EDEADLK);
      CASE(ENAMETOOLONG);
      CASE(ENOLCK);
      CASE(ENOSYS);
      CASE(ENOTEMPTY);
      CASE(ELOOP);
      CASE(ENOMSG);
      CASE(EIDRM);
      CASE(ECHRNG);
      CASE(EL2NSYNC);
      CASE(EL3HLT);
      CASE(EL3RST);
      CASE(ELNRNG);
      CASE(EUNATCH);
      CASE(ENOCSI);
      CASE(EL2HLT);
      CASE(EBADE);
      CASE(EBADR);
      CASE(EXFULL);
      CASE(ENOANO);
      CASE(EBADRQC);
      CASE(EBADSLT);
      CASE(EBFONT);
      CASE(ENOSTR);
      CASE(ENODATA);
      CASE(ETIME);
      CASE(ENOSR);
      CASE(ENONET);
      CASE(ENOPKG);
      CASE(EREMOTE);
      CASE(ENOLINK);
      CASE(EADV);
      CASE(ESRMNT);
      CASE(ECOMM);
      CASE(EPROTO);
      CASE(EMULTIHOP);
      CASE(EDOTDOT);
      CASE(EBADMSG);
      CASE(EOVERFLOW);
      CASE(ENOTUNIQ);
      CASE(EBADFD);
      CASE(EREMCHG);
      CASE(ELIBACC);
      CASE(ELIBBAD);
      CASE(ELIBSCN);
      CASE(ELIBMAX);
      CASE(ELIBEXEC);
      CASE(EILSEQ);
      CASE(ERESTART);
      CASE(ESTRPIPE);
      CASE(EUSERS);
      CASE(ENOTSOCK);
      CASE(EDESTADDRREQ);
      CASE(EMSGSIZE);
      CASE(EPROTOTYPE);
      CASE(ENOPROTOOPT);
      CASE(EPROTONOSUPPORT);
      CASE(ESOCKTNOSUPPORT);
      CASE(EOPNOTSUPP);
      CASE(EPFNOSUPPORT);
      CASE(EAFNOSUPPORT);
      CASE(EADDRINUSE);
      CASE(EADDRNOTAVAIL);
      CASE(ENETDOWN);
      CASE(ENETUNREACH);
      CASE(ENETRESET);
      CASE(ECONNABORTED);
      CASE(ECONNRESET);
      CASE(ENOBUFS);
      CASE(EISCONN);
      CASE(ENOTCONN);
      CASE(ESHUTDOWN);
      CASE(ETOOMANYREFS);
      CASE(ETIMEDOUT);
      CASE(ECONNREFUSED);
      CASE(EHOSTDOWN);
      CASE(EHOSTUNREACH);
      CASE(EALREADY);
      CASE(EINPROGRESS);
      CASE(ESTALE);
      CASE(EUCLEAN);
      CASE(ENOTNAM);
      CASE(ENAVAIL);
      CASE(EISNAM);
      CASE(EREMOTEIO);
      CASE(EDQUOT);
      CASE(ENOMEDIUM);
      CASE(EMEDIUMTYPE);
      CASE(ECANCELED);
      CASE(ENOKEY);
      CASE(EKEYEXPIRED);
      CASE(EKEYREVOKED);
      CASE(EKEYREJECTED);
      CASE(EOWNERDEAD);
      CASE(ENOTRECOVERABLE);
      CASE(ERFKILL);
      CASE(EHWPOISON);
    default: {
      char buf[100];
      sprintf(buf, "errno(%d)", err);
      return string(buf);
    }
  }
}

string sicode_name(int code, int sig) {
  switch (code) {
    CASE(SI_USER);
    CASE(SI_KERNEL);
    CASE(SI_QUEUE);
    CASE(SI_TIMER);
    CASE(SI_MESGQ);
    CASE(SI_ASYNCIO);
    CASE(SI_SIGIO);
    CASE(SI_TKILL);
    CASE(SI_ASYNCNL);
  }

  switch (sig) {
    case SIGSEGV:
      switch (code) {
        CASE(SEGV_MAPERR);
        CASE(SEGV_ACCERR);
      }
      break;
    case SIGTRAP:
      switch (code) {
        CASE(TRAP_BRKPT);
        CASE(TRAP_TRACE);
      }
      break;
    case SIGILL:
      switch (code) {
        CASE(ILL_ILLOPC);
        CASE(ILL_ILLOPN);
        CASE(ILL_ILLADR);
        CASE(ILL_ILLTRP);
        CASE(ILL_PRVOPC);
        CASE(ILL_PRVREG);
        CASE(ILL_COPROC);
        CASE(ILL_BADSTK);
      }
      break;
    case SIGFPE:
      switch (code) {
        CASE(FPE_INTDIV);
        CASE(FPE_INTOVF);
        CASE(FPE_FLTDIV);
        CASE(FPE_FLTOVF);
        CASE(FPE_FLTUND);
        CASE(FPE_FLTRES);
        CASE(FPE_FLTINV);
        CASE(FPE_FLTSUB);
      }
      break;
    case SIGBUS:
      switch (code) {
        CASE(BUS_ADRALN);
        CASE(BUS_ADRERR);
        CASE(BUS_OBJERR);
        CASE(BUS_MCEERR_AR);
        CASE(BUS_MCEERR_AO);
      }
      break;
    case SIGCHLD:
      switch (code) {
        CASE(CLD_EXITED);
        CASE(CLD_KILLED);
        CASE(CLD_DUMPED);
        CASE(CLD_TRAPPED);
        CASE(CLD_STOPPED);
        CASE(CLD_CONTINUED);
      }
      break;
    case SIGPOLL:
      switch (code) {
        CASE(POLL_IN);
        CASE(POLL_OUT);
        CASE(POLL_MSG);
        CASE(POLL_ERR);
        CASE(POLL_PRI);
        CASE(POLL_HUP);
      }
      break;
  }

  char buf[100];
  sprintf(buf, "sicode(%d)", code);
  return string(buf);
}

ostream& operator<<(ostream& stream, const siginfo_t& siginfo) {
  stream << "{signo:" << signal_name(siginfo.si_signo)
         << ",errno:" << errno_name(siginfo.si_errno)
         << ",code:" << sicode_name(siginfo.si_code, siginfo.si_signo);
  switch (siginfo.si_signo) {
    case SIGILL:
    case SIGFPE:
    case SIGSEGV:
    case SIGBUS:
    case SIGTRAP:
      stream << ",addr:" << siginfo.si_addr;
      break;
  }
  stream << "}";
  return stream;
}

int shm_flags_to_mmap_prot(int flags) {
  return PROT_READ | ((flags & SHM_RDONLY) ? 0 : PROT_WRITE) |
         ((flags & SHM_EXEC) ? PROT_EXEC : 0);
}

string xsave_feature_string(uint64_t xsave_features) {
  string ret;
  if (xsave_features & 0x01) {
    ret += "x87 ";
  }
  if (xsave_features & 0x02) {
    ret += "SSE ";
  }
  if (xsave_features & 0x04) {
    ret += "AVX ";
  }
  if (xsave_features & 0x08) {
    ret += "MPX-BNDREGS ";
  }
  if (xsave_features & 0x10) {
    ret += "MPX-BNDCSR ";
  }
  if (xsave_features & 0x20) {
    ret += "AVX512-opmask ";
  }
  if (xsave_features & 0x40) {
    ret += "AVX512-ZMM_Hi256 ";
  }
  if (xsave_features & 0x80) {
    ret += "AVX512-Hi16_ZMM ";
  }
  if (xsave_features & 0x100) {
    ret += "PT ";
  }
  if (xsave_features & 0x200) {
    ret += "PKRU ";
  }
  if (xsave_features & 0x2000) {
    ret += "HDC ";
  }
  if (ret.size() > 0) {
    ret = ret.substr(0, ret.size() - 1);
  }
  return ret;
}

} // namespace rr
