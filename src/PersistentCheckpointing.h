#pragma once

#include "AddressSpace.h"
#include "CheckpointInfo.h"
#include "kernel_abi.h"
#include "log.h"
#include "rr_pcp.capnp.h"
#include <capnp/blob.h>
#include <capnp/message.h>
#include <capnp/serialize-packed.h>
#include <kj/common.h>
namespace rr {

using FrameTime = int64_t;

// Persistent checkpointing related utilities

/** Passed from write_vm to each write_map call. Configures buffer for copying
 * mappings into as well as opening relevant proc fs files */
class WriteVmConfig {
public:
  WriteVmConfig(Task* clone_leader, const char* data_dir,
                size_t buffer_size) noexcept;
  ~WriteVmConfig() { ::munmap(buffer.ptr, buffer.size); }

  Task* clone_leader;
  ScopedFd proc_mem_fd;
  ScopedFd proc_pagemap_fd;
  const char* cp_data_dir;

  struct {
    uint8_t* ptr;
    size_t size;
  } buffer;

  ssize_t pread(ssize_t bytes_read, const KernelMapping& km) const;
};

/* Writes capture `state` to state builder `sb`. */
void write_capture_state(pcp::CapturedState::Builder& sb,
                         const Task::CapturedState& state);

/**
 * Writes the VM of |clone_leader| using the Capnproto |builder|. Checkpoint
 * specific data, like the serialized segments are stored in
 * |checkpoint_data_dir|
 */
void write_vm(Task* clone_leader, rr::pcp::ProcessSpace::Builder builder,
              const std::string& checkpoint_data_dir);

/**
 * Write file |monitor| information to capnproto |builder|
 */
void write_monitor(rr::pcp::FileMonitor::Builder& builder, int fd,
                   FileMonitor* monitor);

/**
 * Restores Task::CapturedState from capnproto data.
 */
Task::CapturedState reconstitute_captured_state(
    SupportedArch arch, const std::vector<CPUIDRecord>& cpuid_records,
    pcp::CapturedState::Reader reader);

void map_private_anonymous(AutoRemoteSyscalls& remote, const KernelMapping& km);

/**
 * Restores contents of `km` by copying contents from a file at `path` into it.
 */
void restore_map_contents(ReplayTask* t, const std::string& path,
                          const KernelMapping& km);

/**
 * Maps a file-backed (read only) segment in `remote.task()`.
 */
void map_region_file(AutoRemoteSyscalls& remote, const KernelMapping& km,
                     const std::string& file_path);

// XXX re-factor this from `replay_syscall.cc` so that we don't duplicate code
// like this. It's identical, but without assertion. Need input from maintainers
// on where to put this.
void init_scratch_memory(ReplayTask* t, const KernelMapping& km);

using CapturedMemory =
    std::vector<std::pair<remote_ptr<void>, std::vector<uint8_t>>>;

void deserialize_fdtable(Task* t, const rr::pcp::ProcessSpace::Reader& reader);

} // namespace rr