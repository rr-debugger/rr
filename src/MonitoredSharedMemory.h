/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_MONITORED_SHARED_MEMORY_H_
#define RR_MONITORED_SHARED_MEMORY_H_

#include <memory>

#include "AddressSpace.h"

namespace rr {

class RecordTask;

/**
 * Support tracees that share memory read-only with a non-tracee that
 * writes to the memory. Currently this just supports limited cases that
 * suffice for dconf: no remapping, coalescing or splitting of the memory is
 * allowed (|subrange| below just asserts). It doesn't handle mappings where
 * the mapping has more pages than the file.
 *
 * After such memory is mapped in the tracee, we also map it in rr at |real_mem|
 * and replace the tracee's mapping with a "shadow buffer" that's only shared
 * with rr. Then periodically rr reads the real memory, and if it doesn't match
 * the shadow buffer, we update the shadow buffer with the new values and
 * record that we did so.
 *
 * Currently we check the real memory after each syscall exit. This ensures
 * that if the tracee is woken up by some IPC mechanism (or after sched_yield),
 * it will get a chance to see updated memory values.
 */
class MonitoredSharedMemory {
public:
  ~MonitoredSharedMemory();

  typedef std::shared_ptr<MonitoredSharedMemory> shr_ptr;

  static void maybe_monitor(RecordTask* t, const std::string& file_name,
                            const AddressSpace::Mapping& m, int tracee_fd,
                            uint64_t offset);

  static void check_all(RecordTask* t);

  shr_ptr subrange(uintptr_t start, uintptr_t size);

private:
  void check_for_changes(RecordTask* t, AddressSpace::Mapping& m);

  MonitoredSharedMemory(uint8_t* real_mem, size_t size)
      : real_mem(real_mem), size(size) {}
  uint8_t* real_mem;
  size_t size;
};

} // namespace rr

#endif /* RR_MONITORED_SHARED_MEMORY_H_ */
