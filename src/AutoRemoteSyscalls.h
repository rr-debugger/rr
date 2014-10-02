/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_AUTO_REMOTE_SYSCALLS_H_
#define RR_AUTO_REMOTE_SYSCALLS_H_

#include <string.h>

#include <vector>

#include "Registers.h"
#include "ScopedFd.h"

class AutoRemoteSyscalls;
class Task;

/**
 * Helpers to make remote syscalls on behalf of a Task.  Usage looks
 * like
 *
 *    AutoRemoteSyscalls remote(t); // prepare remote syscalls
 *    remote.syscall(syscall_number_for_open(remote.arch()), ...); // make
 *syscalls
 *    ...
 *    // when |remote| goes out of scope, remote syscalls are finished
 */

/**
 * Cookie used to restore stomped memory, usually prepared as the
 * argument to a remote syscall.
 */
class AutoRestoreMem {
public:
  /**
   * Write |mem| into address space of the Task prepared for
   * remote syscalls in |remote|, in such a way that the write
   * will be undone.  The address of the tmp mem space is
   * available via operator void*().
   */
  AutoRestoreMem(AutoRemoteSyscalls& remote, const uint8_t* mem,
                 ssize_t num_bytes)
      : remote(remote) {
    init(mem, num_bytes);
  }

  /**
   * Convenience constructor for pushing a C string |str|, including
   * the trailing '\0' byte.
   */
  AutoRestoreMem(AutoRemoteSyscalls& remote, const char* str) : remote(remote) {
    init((const uint8_t*)str, strlen(str) + 1 /*null byte*/);
  }

  ~AutoRestoreMem();

  remote_ptr<void> get() const { return addr; }

private:
  void init(const uint8_t* mem, ssize_t num_bytes);

  AutoRemoteSyscalls& remote;
  /* Address of tmp mem. */
  remote_ptr<void> addr;
  /* Pointer to saved data. */
  std::vector<uint8_t> data;
  /* (We keep this around for error checking.) */
  remote_ptr<void> saved_sp;
  /* Length of tmp mem. */
  size_t len;

  AutoRestoreMem& operator=(const AutoRestoreMem&) = delete;
  AutoRestoreMem(const AutoRestoreMem&) = delete;
  void* operator new(size_t) = delete;
  void operator delete(void*) = delete;
};

/**
 * RAII helper to prepare a Task for remote syscalls and undo any
 * preparation upon going out of scope.
 */
class AutoRemoteSyscalls {
public:
  /**
   * Prepare |t| for a series of remote syscalls.
   *
   * NBBB!  Before preparing for a series of remote syscalls,
   * the caller *must* ensure the callee will not receive any
   * signals.  This code does not attempt to deal with signals.
   */
  AutoRemoteSyscalls(Task* t);
  /**
   * Undo in |t| any preparations that were made for a series of
   * remote syscalls.
   */
  ~AutoRemoteSyscalls();

  /**
   * "Initial" registers saved from the target task.
   *
   * NB: a non-const reference is returned because some power
   * users want to update the registers that are restored after
   * finishing remote syscalls.  Perhaps these users should be
   * fixed, or you should just be careful.
   */
  Registers& regs() { return initial_regs; }

  /**
   * Undo any preparations to make remote syscalls in the context of |t|.
   *
   * This is usually called automatically by the destructor;
   * don't call it directly unless you really know what you'd
   * doing.  *ESPECIALLY* don't call this on a |t| other than
   * the one passed to the contructor, unless you really know
   * what you're doing.
   */
  void restore_state_to(Task* t);

  /**
   * Make |syscallno| with variadic |args| (limited to 6 on
   * x86).  Return the raw kernel return value.
   */
  template <typename... Rest> long syscall(int syscallno, Rest... args) {
    Registers callregs = regs();
    // The first syscall argument is called "arg 1", so
    // our syscall-arg-index template parameter starts
    // with "1".
    return syscall_helper<1>(syscallno, callregs, args...);
  }

  /** The Task in the context of which we're making syscalls. */
  Task* task() const { return t; }

  /**
   * A small helper to get at the Task's arch.
   * Out-of-line to avoid including task.h here.
   */
  SupportedArch arch() const;

  /**
   * Arranges for 'fd' to be transmitted to this process and returns
   * our opened version of it.
   */
  ScopedFd retrieve_fd(int fd);

private:
  /**
   * Remotely invoke in |t| the specified syscall with the given
   * arguments.  The arguments must of course be valid in |t|,
   * and no checking of that is done by this function.
   *
   * If |wait| is |WAIT|, the syscall is finished in |t| and the
   * result is returned.  Otherwise if it's |DONT_WAIT|, the
   * syscall is initiated but *not* finished in |t|, and the
   * return value is undefined.  Call |wait_remote_syscall()| to
   * finish the syscall and get the return value.
   */
  enum SyscallWaiting {
    WAIT = 1,
    DONT_WAIT = 0
  };
  long syscall_helper(SyscallWaiting wait, int syscallno, Registers& callregs);

  /**
   * Wait for the |DONT_WAIT| syscall |syscallno| initiated by
   * |remote_syscall()| to finish, returning the result.
   */
  long wait_syscall(int syscallno);

  /**
   * "Recursively" build the set of syscall registers in
   * |callregs|.  |Index| is the syscall arg that will be set to
   * |arg|, and |args| are the remaining arguments.
   */
  template <int Index, typename T, typename... Rest>
  long syscall_helper(int syscallno, Registers& callregs, T arg, Rest... args) {
    callregs.set_arg<Index>(arg);
    return syscall_helper<Index + 1>(syscallno, callregs, args...);
  }
  /**
   * "Recursion" "base case": no more arguments to build, so
   * just make the syscall and return the kernel return value.
   */
  template <int Index> long syscall_helper(int syscallno, Registers& callregs) {
    return syscall_helper(WAIT, syscallno, callregs);
  }

  Task* t;
  Registers initial_regs;
  remote_ptr<uint8_t> initial_ip;
  int pending_syscallno;
  static const uint8_t syscall_insn[2];
  uint8_t code_buffer[sizeof(syscall_insn)];

  AutoRemoteSyscalls& operator=(const AutoRemoteSyscalls&) = delete;
  AutoRemoteSyscalls(const AutoRemoteSyscalls&) = delete;
  void* operator new(size_t) = delete;
  void operator delete(void*) = delete;
};

#endif // RR_AUTO_REMOTE_SYSCALLS_H_
