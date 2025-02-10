#include "CheckpointInfo.h"
#include "GdbServerConnection.h"
#include "ReplayTimeline.h"
#include "ScopedFd.h"
#include "rr_pcp.capnp.h"
#include "util.h"
#include <algorithm>
#include <capnp/blob.h>
#include <capnp/message.h>
#include <capnp/serialize-packed.h>
#include <cstddef>
#include <dirent.h>
#include <sstream>

namespace rr {

MarkData::MarkData(const ReplayTimeline::Mark& m)
    : time(m.get_key().trace_time),
      ticks(m.get_key().ticks),
      step_key(m.get_key().step_key.as_int()),
      ticks_at_event_start(m.get_internal()->ticks_at_event_start),
      regs(m.regs()),
      extra_regs(m.extra_regs()),
      return_addresses(m.get_internal()->proto.return_addresses),
      singlestep_to_next_mark_no_signal(
          m.get_internal()->singlestep_to_next_mark_no_signal),
      arch(m.get_internal()->extra_regs.arch()) {}

MarkData::MarkData(rr::pcp::MarkData::Reader reader,
                   const CPUIDRecords& cpuid_recs)
    : time(reader.getTime()),
      ticks(reader.getTicks()),
      step_key(reader.getStepKey()),
      ticks_at_event_start(reader.getTicksAtEventStart()),
      regs(),
      extra_regs(),
      return_addresses(),
      singlestep_to_next_mark_no_signal(
          reader.getSinglestepToNextMarkNoSignal()),
      arch(from_trace_arch(reader.getArch())) {
  regs.set_arch(arch);
  regs.set_from_trace(arch, reader.getRegs().getRaw().begin(),
                      reader.getRegs().getRaw().size());
  auto eregs = reader.getExtraRegs().getRaw();
  set_extra_regs_from_raw(arch, cpuid_recs, eregs, extra_regs);
  auto i = 0;
  for (auto rs : reader.getReturnAddresses()) {
    return_addresses.addresses[i++] = rs;
  }
}

static std::vector<string> checkpoint_directories(const string& trace_dir) {
  std::vector<string> result;
  auto tracedir = opendir(trace_dir.c_str());
  if (!tracedir) {
    return {};
  }
  for (dirent* e = readdir(tracedir); e; e = readdir(tracedir)) {
    std::string_view filename{ e->d_name };
    if (filename.find("checkpoint-") == 0) {
      stringstream metadata_file{};
      metadata_file << trace_dir << '/' << filename;
      auto f = metadata_file.str();
      struct stat buffer;
      if (stat(f.c_str(), &buffer) == 0) {
        result.push_back(std::move(f));
      }
    }
  }
  closedir(tracedir);
  return result;
}

std::vector<CheckpointInfo> get_checkpoint_infos(
    const std::string& trace_dir, const CPUIDRecords& cpuid_recs) {

  std::vector<CheckpointInfo> checkpoints;
  for (auto checkpoint_dir : checkpoint_directories(trace_dir)) {
    auto metadata_file = checkpoint_dir + "/metadata";
    ScopedFd fd(metadata_file.c_str(), O_RDONLY);
    if (!fd.is_open()) {
      continue;
    }
    capnp::PackedFdMessageReader reader(fd);
    auto checkpointsInfoReader = reader.getRoot<pcp::CheckpointInfo>();
    auto info =
        CheckpointInfo{ checkpoint_dir, checkpointsInfoReader, cpuid_recs };
    checkpoints.push_back(info);
  }

  std::sort(checkpoints.begin(), checkpoints.end(),
            [](CheckpointInfo& a, CheckpointInfo& b) {
              return a.clone_data.time <= b.clone_data.time;
            });
  return checkpoints;
}

bool CheckpointInfo::serialize(ReplaySession& session) {
  // and write a new one
  auto fd = open_for_write();
  if (!fd.is_open() && errno == EEXIST) {
    // we just nope out, if it exists already. 1 checkpoint per FrameTime
    // allowed currently.
    std::cout << "path already exists: " << capnp_directory << std::endl;
    return false;
  } else if (!fd.is_open()) {
    FATAL() << "failed to open file " << capnp_directory;
  }

  capnp::MallocMessageBuilder message;
  pcp::CheckpointInfo::Builder cp_entry =
      message.initRoot<pcp::CheckpointInfo>();
  auto clone_writer = cp_entry.getCloneCompletion();
  session.serialize_checkpoint(clone_writer, *this);
  cp_entry.setId(unique_id);
  auto tuid = cp_entry.initLastContinueTask();
  tuid.setGroupId(last_continue_task.tguid.tid());
  tuid.setGroupSerial(last_continue_task.tguid.serial());
  tuid.setTaskId(last_continue_task.tuid.tid());
  tuid.setTaskSerial(last_continue_task.tuid.serial());

  cp_entry.setWhere(str_to_data(where));
  cp_entry.setNextSerial(next_serial);
  auto statsWriter = cp_entry.getStatistics();
  statsWriter.setBytesWritten(stats.bytes_written);
  statsWriter.setSyscallsPerformed(stats.syscalls_performed);
  statsWriter.setTicksProcessed(stats.ticks_processed);

  const auto mark_data_serializer = [](const MarkData& mark_data,
                                       auto& builder) {
    builder.setTime(mark_data.time);
    builder.setStepKey(mark_data.step_key);
    builder.setTicks(mark_data.ticks);
    builder.initRegs().setRaw(regs_to_raw(mark_data.regs));
    auto ras = builder.initReturnAddresses(8);
    for (auto i = 0; i < 8; i++) {
      ras.set(i, mark_data.return_addresses.addresses[i].as_int());
    }
    builder.initExtraRegs().setRaw(extra_regs_to_raw(mark_data.extra_regs));
    builder.setTicksAtEventStart(mark_data.ticks_at_event_start);
    builder.setSinglestepToNextMarkNoSignal(
        mark_data.singlestep_to_next_mark_no_signal);
    builder.setArch(to_trace_arch(mark_data.arch));
  };

  if (is_explicit()) {
    auto explicit_builder = cp_entry.initExplicit();
    mark_data_serializer(clone_data, explicit_builder);
  } else {
    auto non_explicit = cp_entry.initNonExplicit();
    // mark that holds _actual_ session clone
    auto mark_with_clone = non_explicit.initCloneMark();
    mark_data_serializer(clone_data, mark_with_clone);
    // mark that only holds a mark. It gets very messy quickly, wrt to Marks,
    // Clones, Checkpoints.
    auto mark_with_gdb_checkpoint = non_explicit.initCheckpointMark();
    mark_data_serializer(*non_explicit_mark_data, mark_with_gdb_checkpoint);
  }
  capnp::writePackedMessageToFd(fd, message);
  return true;
}

bool CheckpointInfo::exists_on_disk() const {
  struct stat buf;
  return stat(capnp_file_path().c_str(), &buf) == 0;
}

void CheckpointInfo::set_capnp_directory(const ReplayTimeline::Mark& mark) {

  capnp_directory = mark.get_checkpoint()->trace_reader().dir() +
                    "/checkpoint-" + std::to_string(mark.time());
}

CheckpointInfo::CheckpointInfo(const Checkpoint& c)
    : unique_id(CheckpointInfo::generate_unique_id(c.unique_id)),
      last_continue_task(c.last_continue_task),
      where(c.where),
      clone_data(c.mark),
      non_explicit_mark_data(nullptr) {
  DEBUG_ASSERT(c.is_explicit == Checkpoint::EXPLICIT &&
               c.mark.has_rr_checkpoint());
  // can't assert before ctor, set these values here.
  next_serial = c.mark.get_checkpoint()->current_task_serial();
  stats = c.mark.get_checkpoint()->statistics();
  LOG(debug) << "checkpoint clone at " << clone_data.time
             << "; GDB checkpoint at " << clone_data.time;
  set_capnp_directory(c.mark);
}

CheckpointInfo::CheckpointInfo(ExtendedTaskId last_continue,
                               const ReplayTimeline::Mark& mark_with_checkpoint)
    : unique_id(CheckpointInfo::generate_unique_id()),
      last_continue_task(last_continue),
      where("Unknown"),
      next_serial(mark_with_checkpoint.get_checkpoint()->current_task_serial()),
      clone_data(mark_with_checkpoint),
      non_explicit_mark_data(nullptr),
      stats(mark_with_checkpoint.get_checkpoint()->statistics()) {
  LOG(debug) << "checkpoint clone at " << clone_data.time
             << "; GDB checkpoint at " << clone_data.time;
  set_capnp_directory(mark_with_checkpoint);
}

CheckpointInfo::CheckpointInfo(const Checkpoint& non_explicit_cp,
                               const ReplayTimeline::Mark& mark_with_clone)
    : unique_id(CheckpointInfo::generate_unique_id(non_explicit_cp.unique_id)),
      last_continue_task(non_explicit_cp.last_continue_task),
      where(non_explicit_cp.where),
      next_serial(mark_with_clone.get_checkpoint()->current_task_serial()),
      clone_data(mark_with_clone),
      non_explicit_mark_data(new MarkData{ non_explicit_cp.mark }),
      stats(mark_with_clone.get_checkpoint()->statistics()) {
  DEBUG_ASSERT(non_explicit_cp.is_explicit == Checkpoint::NOT_EXPLICIT &&
               !non_explicit_cp.mark.has_rr_checkpoint() &&
               "Constructor meant for non explicit checkpoints");
  // XXX we give this checkpoint the id (and name/path) of the actual cloned
  // session data, so that multiple non explicit checkpoints later on, can
  // reference the same clone data (not yet implemented)
  LOG(debug) << "checkpoint clone at " << clone_data.time
             << "; GDB checkpoint at " << non_explicit_mark_data->time;
  set_capnp_directory(mark_with_clone);
}

CheckpointInfo::CheckpointInfo(std::string metadata_file,
                               rr::pcp::CheckpointInfo::Reader reader,
                               const CPUIDRecords& cpuid_recs)
    : capnp_directory(std::move(metadata_file)),
      unique_id(reader.getId()),
      where(data_to_str(reader.getWhere())),
      next_serial(reader.getNextSerial()),
      clone_data(reader.isExplicit() ? reader.getExplicit()
                                     : reader.getNonExplicit().getCloneMark(),
                 cpuid_recs),
      non_explicit_mark_data(
          reader.isNonExplicit()
              ? new MarkData{ reader.getNonExplicit().getCheckpointMark(),
                              cpuid_recs }
              : nullptr),
      stats() {
  auto t = reader.getLastContinueTask();
  last_continue_task = ExtendedTaskId{ { t.getGroupId(), t.getGroupSerial() },
                                       { t.getTaskId(), t.getTaskSerial() } };
  auto s = reader.getStatistics();
  stats.bytes_written = s.getBytesWritten();
  stats.syscalls_performed = s.getSyscallsPerformed();
  stats.ticks_processed = s.getTicksProcessed();
}

void CheckpointInfo::delete_from_disk() {
  const auto remove_file = [](auto path_data) {
    const auto path = data_to_str(path_data);
    if (remove(path.c_str()) != 0) {
      LOG(error) << "Failed to remove " << path;
    }
  };
  ScopedFd fd(capnp_directory.c_str(), O_RDONLY);
  capnp::PackedFdMessageReader datum(fd);
  pcp::CloneCompletionInfo::Reader cc_reader =
      datum.getRoot<pcp::CloneCompletionInfo>();
  const auto addr_spaces = cc_reader.getAddressSpaces();
  for (const auto& as : addr_spaces) {
    const auto mappings_data = as.getProcessSpace().getVirtualAddressSpace();
    for (const auto& m : mappings_data) {
      switch (m.getMapType().which()) {
        case pcp::KernelMapping::MapType::FILE:
          remove_file(m.getMapType().getFile().getContentsPath());
          break;
        case pcp::KernelMapping::MapType::SHARED_ANON:
          remove_file(m.getMapType().getSharedAnon().getContentsPath());
          break;
        case pcp::KernelMapping::MapType::PRIVATE_ANON:
          remove_file(m.getMapType().getPrivateAnon().getContentsPath());
          break;
        case pcp::KernelMapping::MapType::GUARD_SEGMENT:
          break;
        case pcp::KernelMapping::MapType::SYSCALL_BUFFER:
          remove_file(m.getMapType().getSyscallBuffer().getContentsPath());
          break;
        case pcp::KernelMapping::MapType::RR_PAGE:
          remove_file(m.getMapType().getRrPage().getContentsPath());
          break;
      }
    }
  }

  remove(capnp_directory.c_str());
  remove(data_directory().c_str());
  if (exists_on_disk()) {
    LOG(error) << "Couldn't remove persistent checkpoint data (or directory)";
  }
}

ScopedFd CheckpointInfo::open_for_read() const {
  DEBUG_ASSERT(exists_on_disk() && "This checkpoint has not been serialized; "
                                   "or the index file has been removed.");
  auto file = ScopedFd(capnp_file_path().c_str(), O_RDONLY);
  if (!file.is_open())
    FATAL() << "Couldn't open checkpoint data " << file;
  return file;
}

ScopedFd CheckpointInfo::open_for_write() const {
  DEBUG_ASSERT(!exists_on_disk() &&
               "Already serialized checkpoints shouldn't be re-written");
  auto file =
      ScopedFd(capnp_file_path().c_str(), O_EXCL | O_CREAT | O_RDWR, 0700);
  if (!file.is_open())
    FATAL() << "Couldn't open checkpoint file for writing "
            << capnp_file_path();
  return file;
}

std::string CheckpointInfo::capnp_file_path() const {
  return capnp_directory + "/metadata";
}

const std::string& CheckpointInfo::data_directory() const {
  return capnp_directory;
}

/*static*/ size_t CheckpointInfo::generate_unique_id(size_t id) {
  // if we haven't been set already, generate a unique "random" id
  if (id == 0) {
    timeval t;
    gettimeofday(&t, nullptr);
    auto cp_id = (t.tv_sec * 1000 + t.tv_usec / 1000);
    return cp_id;
  } else {
    return id;
  }
}

} // namespace rr