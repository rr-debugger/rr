/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_MONKEYPATCHER_H_
#define RR_MONKEYPATCHER_H_

#include <vector>

#include "preload/preload_interface.h"

#include "remote_ptr.h"

class Task;

/**
 * A class encapsulating patching state. There is one instance of this
 * class per tracee address space. Currently this class performs the following
 * tasks:
 *
 * 1) Patch the VDSO's user-space-only implementation of certain system calls
 * (e.g. gettimeofday) to do a proper kernel system call instead, so rr can
 * trap and record it (x86-64 only).
 *
 * 2) Patch the VDSO __kernel_vsyscall fast-system-call stub to redirect to
 * our vsyscall hook in the preload library (x86 only).
 */
class Monkeypatcher {
public:
  Monkeypatcher() {}

  /**
   * Apply any necessary patching immediately after exec.
   * In this hook we patch everything that doesn't depend on the preload
   * library being loaded.
   */
  void patch_after_exec(Task* t);

  /**
   * During librrpreload initialization, apply patches that require the
   * preload library to be initialized.
   */
  void patch_at_preload_init(Task* t);

  void init_dynamic_syscall_patching(
      Task* t, int syscall_patch_hook_count,
      remote_ptr<syscall_patch_hook> syscall_patch_hooks);

  std::vector<syscall_patch_hook> syscall_hooks;
};

#endif /* RR_MONKEYPATCHER_H_ */
