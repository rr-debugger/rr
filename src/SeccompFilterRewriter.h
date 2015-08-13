/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_SECCOMP_FILTER_REWRITER_H_
#define RR_SECCOMP_FILTER_REWRITER_H_

#include <assert.h>

#include <cstdint>
#include <unordered_map>
#include <vector>

class Task;

/**
 * Object to support install_patched_seccomp_filter.
 */
class SeccompFilterRewriter {
public:
  /**
   * Assuming |t| is set up for a prctl or seccomp syscall that
   * installs a seccomp-bpf filter, patch the filter to signal the tracer
   * instead of silently delivering an errno, and install it.
   */
  void install_patched_seccomp_filter(Task* t);

  uint32_t map_filter_data_to_real_result(uint16_t value) {
    assert(value < index_to_result.size());
    return index_to_result[value];
  }

private:
  /**
   * Seccomp filters can return 32-bit result values. We need to map all of
   * them into a single 16 bit data field. Fortunately (so far) all the
   * filters we've seen return constants, so there aren't too many distinct
   * values we need to deal with. For each constant value that gets returned,
   * we'll add it as the key in |result_map|, with the corresponding value
   * being the 16-bit data value that our rewritten filter returns.
   */
  std::unordered_map<uint32_t, uint16_t> result_to_index;
  std::vector<uint32_t> index_to_result;
};

#endif // RR_SECCOMP_FILTER_REWRITER_H_
