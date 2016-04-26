/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_AUTO_REMOTE_SYSCALLS_H_
#define RR_AUTO_REMOTE_SYSCALLS_H_

#include <string.h>

#include <vector>

#include "Registers.h"
#include "ScopedFd.h"
#include "Task.h"

namespace rr {

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
   * will be undone.  The address of the reserved mem space is
   * available via |get|.
   * If |mem| is null, data is not written, only the space is reserved.
   */
  AutoRestoreMem(AutoRemoteSyscalls& remote, const void* mem, ssize_t num_bytes)
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

  /**
   * Get a pointer to the reserved memory.
   */
  remote_ptr<void> get() const { return addr; }

  /**
   * Return size of reserved memory buffer.
   */
  size_t size() const { return data.size(); }

private:
  void init(const void* mem, ssize_t num_bytes);

  AutoRemoteSyscalls& remote;
  /* Address of tmp mem. */
  remote_ptr<void> addr;
  /* Saved data. */
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
  enum MemParamsEnabled { ENABLE_MEMORY_PARAMS, DISABLE_MEMORY_PARAMS };

  /**
   * Prepare |t| for a series of remote syscalls.
   *
   * NBBB!  Before preparing for a series of remote syscalls,
   * the caller *must* ensure the callee will not receive any
   * signals.  This code does not attempt to deal with signals.
   */
  AutoRemoteSyscalls(Task* t,
                     MemParamsEnabled enable_mem_params = ENABLE_MEMORY_PARAMS);
  /**
   * Undo in |t| any preparations that were made for a series of
   * remote syscalls.
   */
  ~AutoRemoteSyscalls();

  /**
   * If t's stack pointer doesn't look valid, temporarily adjust it to
   * the top of *some* stack area.
   */
  void maybe_fix_stack_pointer();

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
    syscall_helper<1>(syscallno, callregs, args...);
    return t->regs().syscall_result_signed();
  }

  template <typename... Rest>
  long infallible_syscall(int syscallno, Rest... args) {
    Registers callregs = regs();
    // The first syscall argument is called "arg 1", so
    // our syscall-arg-index template parameter starts
    // with "1".
    syscall_helper<1>(syscallno, callregs, args...);
    check_syscall_result(syscallno);
    return t->regs().syscall_result_signed();
  }

  template <typename... Rest>
  remote_ptr<void> infallible_syscall_ptr(int syscallno, Rest... args) {
    Registers callregs = regs();
    syscall_helper<1>(syscallno, callregs, args...);
    check_syscall_result(syscallno);
    return t->regs().syscall_result();
  }

  /**
   * Remote mmap syscalls are common and non-trivial due to the need to
   * select either mmap2 or mmap.
   */
  remote_ptr<void> infallible_mmap_syscall(remote_ptr<void> addr, size_t length,
                                           int prot, int flags, int child_fd,
                                           uint64_t offset_pages);

  int64_t infallible_lseek_syscall(int fd, int64_t offset, int whence);

  /** The Task in the context of which we're making syscalls. */
  Task* task() const { return t; }

  /**
   * A small helper to get at the Task's arch.
   * Out-of-line to avoid including Task.h here.
   */
  SupportedArch arch() const;

  /**
   * Arranges for 'fd' to be transmitted to this process and returns
   * our opened version of it.
   */
  ScopedFd retrieve_fd(int fd);

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
  enum SyscallWaiting { WAIT = 1, DONT_WAIT = 0 };
  void syscall_helper(SyscallWaiting wait, int syscallno, Registers& callregs);

private:
  /**
   * Wait for the |DONT_WAIT| syscall |syscallno| initiated by
   * |remote_syscall()| to finish, returning the result.
   * |syscallno| is only for assertion checking. If no value is passed in,
   * everything should work without the assertion checking.
   */
  void wait_syscall(int syscallno = -1);

  void check_syscall_result(int syscallno);

  /**
   * "Recursively" build the set of syscall registers in
   * |callregs|.  |Index| is the syscall arg that will be set to
   * |arg|, and |args| are the remaining arguments.
   */
  template <int Index, typename T, typename... Rest>
  void syscall_helper(int syscallno, Registers& callregs, T arg, Rest... args) {
    callregs.set_arg<Index>(arg);
    syscall_helper<Index + 1>(syscallno, callregs, args...);
  }
  /**
   * "Recursion" "base case": no more arguments to build, so
   * just make the syscall and return the kernel return value.
   */
  template <int Index> void syscall_helper(int syscallno, Registers& callregs) {
    syscall_helper(WAIT, syscallno, callregs);
  }

  template <typename Arch> ScopedFd retrieve_fd_arch(int fd);

  Task* t;
  Registers initial_regs;
  remote_code_ptr initial_ip;
  remote_ptr<void> initial_sp;
  int pending_syscallno;

  AutoRemoteSyscalls& operator=(const AutoRemoteSyscalls&) = delete;
  AutoRemoteSyscalls(const AutoRemoteSyscalls&) = delete;
  void* operator new(size_t) = delete;
  void operator delete(void*) = delete;
};

} // namespace rr

#endif // RR_AUTO_REMOTE_SYSCALLS_H_
