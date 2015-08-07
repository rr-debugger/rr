/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_SECCOMP_FILTER_REWRITER_H_
#define RR_SECCOMP_FILTER_REWRITER_H_

class Task;

/**
 * Object to support install_patched_seccomp_filter.
 */
class SeccompFilterRewriter {
public:
  /**
   * Assuming |t| is set up for a prctl or seccomp syscall that
   * installs a seccomp-bpf filter, patch the filter to signal the tracer
   * instead
   * of silently delivering an errno, and install it.
   */
  void install_patched_seccomp_filter(Task* t);
};

#endif // RR_SECCOMP_FILTER_REWRITER_H_
