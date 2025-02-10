#pragma once

#include "ExtraRegisters.h"
#include "GdbServer.h"
#include "GdbServerConnection.h"
#include "ReplayTimeline.h"
#include "ReturnAddressList.h"
#include "kernel_abi.h"
#include "rr_pcp.capnp.h"
#include "util.h"
#include <dirent.h>
#include <sys/time.h>

namespace rr {

using CPUIDRecords = std::vector<CPUIDRecord>;

/**
 * CheckpointInfo and MarkData are intermediary types between de/serialization
 * of checkpoints and marks. These types are added to not intrude in Checkpoint,
 * Mark, InternalMarks, ProtoMark etc, to make sure that the implementation of
 * persistent checkpoints do not break any guarantees or invariants provided by
 * those types in normal record/replay.
 */

/**
 * `MarkData` flattens that "hierarchy" representing `Mark`, `InternalMark` and
 * `ProtoMark` required for de/serialization. When deserializing this hierarchy
 * is rebuilt from `MarkData`
 */
struct MarkData {
  // Constructor when serializing
  MarkData(const ReplayTimeline::Mark& m);
  // Constructor when de-serializing
  MarkData(rr::pcp::MarkData::Reader reader, const CPUIDRecords& cpuid_recs);

  FrameTime time;
  Ticks ticks;
  int step_key;
  Ticks ticks_at_event_start;
  Registers regs;
  ExtraRegisters extra_regs;
  ReturnAddressList return_addresses;
  bool singlestep_to_next_mark_no_signal;
  SupportedArch arch;
};

class CheckpointInfo {
  void set_capnp_directory(const ReplayTimeline::Mark& mark);

public:
  /**
   * For `GDBServer` users of explicit checkpoints.
   */
  CheckpointInfo(const Checkpoint& checkpoint);

  /**
   * For `GDBServer` users where a non explicit checkpoint was set.
   * `mark_with_clone` is the mark which holds the actual checkpoint / clone,
   * which is some arbitrary event time before actual GDB checkpoint.
   */
  CheckpointInfo(const Checkpoint& checkpoint,
                 const ReplayTimeline::Mark& mark_with_clone);

  /* For `CreateCheckpointsCommand` users (rr create-checkpoints command) */
  CheckpointInfo(ExtendedTaskId last_continue_task,
                 const ReplayTimeline::Mark& mark_with_checkpoint);
  // When deserializing from capnproto stream
  CheckpointInfo(std::string metadata_file,
                 rr::pcp::CheckpointInfo::Reader reader,
                 const CPUIDRecords& cpuid_recs);

  bool serialize(ReplaySession& session);
  bool exists_on_disk() const;
  void delete_from_disk();

  ScopedFd open_for_read() const;
  ScopedFd open_for_write() const;
  std::string capnp_file_path() const;
  const std::string& data_directory() const;

  /**
   * Returns event time for this checkpoint
   */
  FrameTime event_time() const { return clone_data.time; }

  static size_t generate_unique_id(size_t id = 0);

  friend bool operator==(const CheckpointInfo& lhs, const CheckpointInfo& rhs) {
    return lhs.capnp_directory == rhs.capnp_directory;
  }

  bool is_explicit() const { return non_explicit_mark_data == nullptr; }

  // Path to file containing filled out capnproto schema for this checkpoint
  std::string capnp_directory;
  size_t unique_id;
  ExtendedTaskId last_continue_task;
  std::string where;
  uint32_t next_serial;
  // MarkData collected from a Mark with a clone (either an explicit checkpoint,
  // or the first found clone before a non-explicit checkpoint)
  MarkData clone_data;
  // (optional) MarkData collected from a Mark without a clone (in the case of
  // non explicit checkpoints)
  std::shared_ptr<MarkData> non_explicit_mark_data;
  Session::Statistics stats;
};

/**
 * Returns the path of checkpoint index file, given the dir `trace_dir`
 */
std::string checkpoints_index_file(const std::string& trace_dir);

/**
 * Retrieve list of persistent checkpoints in `trace_dir` sorted in ascending
 * order by event time.
 */
std::vector<CheckpointInfo> get_checkpoint_infos(
    const std::string& trace_dir, const CPUIDRecords& cpuid_recs);

} // namespace rr