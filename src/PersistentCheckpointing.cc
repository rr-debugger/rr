#include "PersistentCheckpointing.h"
#include "AutoRemoteSyscalls.h"
#include "BpfMapMonitor.h"
#include "CheckpointInfo.h"
#include "EmuFs.h"
#include "FileMonitor.h"
#include "MagicSaveDataMonitor.h"
#include "MmappedFileMonitor.h"
#include "NonvirtualPerfCounterMonitor.h"
#include "ODirectFileMonitor.h"
#include "PidFdMonitor.h"
#include "PreserveFileMonitor.h"
#include "ProcFdDirMonitor.h"
#include "ProcMemMonitor.h"
#include "ProcStatMonitor.h"
#include "RRPageMonitor.h"
#include "ReplayTask.h"
#include "ScopedFd.h"
#include "Session.h"
#include "StdioMonitor.h"
#include "SysCpuMonitor.h"
#include "Task.h"
#include "TaskishUid.h"
#include "TraceFrame.h"
#include "TraceStream.h"
#include "VirtualPerfCounterMonitor.h"
#include "kernel_abi.h"
#include "log.h"
#include "replay_syscall.h"
#include "rr_pcp.capnp.h"
#include "util.h"
#include <algorithm>
#include <asm-generic/mman-common.h>
#include <cstdint>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <tuple>

namespace rr {

#define PAGE_PRESENT(page_map_entry) page_map_entry & (1ul << 63)
#define PAGE_SWAPPED(page_map_entry) page_map_entry & (1ul << 62)
#define PAGE_FILE_OR_SHARED_ANON(page_map_entry) page_map_entry & (1ul << 61)
#define FILE_OP_FATAL(file)                                                    \
  FATAL() << "write_map failed for " << std::string{ file.get() } << " "
constexpr auto PRIVATE_ANON = MAP_ANONYMOUS | MAP_PRIVATE;

static std::string file_name_of(const std::string& path) {
  auto pos = path.rfind("/");
  // means we're an "ok" filename (ok, means we have no path components - we're
  // either empty or just a file name)
  if (pos == std::string::npos) {
    return path;
  }
  return path.substr(pos + 1);
}

WriteVmConfig::WriteVmConfig(Task* clone_leader, const char* data_dir,
                             size_t buffer_size) noexcept
    : clone_leader(clone_leader), cp_data_dir(data_dir) {
  const auto procfs_mem = clone_leader->proc_mem_path();
  const auto procfs_pagemap = clone_leader->proc_pagemap_path();
  proc_mem_fd = ScopedFd{ procfs_mem.c_str(), O_RDONLY };
  ASSERT(clone_leader, proc_mem_fd.is_open())
      << "Serializing VM for " << clone_leader->rec_tid
      << " failed. Couldn't open " << procfs_mem;
  proc_pagemap_fd = ScopedFd{ procfs_pagemap.c_str(), O_RDONLY };
  ASSERT(clone_leader, proc_pagemap_fd.is_open())
      << "Serializing VM for " << clone_leader->rec_tid
      << " failed. Couldn't open " << proc_pagemap_fd;
  buffer = { .ptr =
                 (uint8_t*)::mmap(nullptr, buffer_size, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
             .size = buffer_size };
  ASSERT(clone_leader, buffer.ptr != MAP_FAILED)
      << "Failed to mmap buffer with capacity " << buffer_size;
}

ssize_t WriteVmConfig::pread(ssize_t bytes_read,
                             const KernelMapping& km) const {
  DEBUG_ASSERT(bytes_read != 1 &&
               "you've passed in the 'invalid pread result' as bytes_read");
  const auto current_read =
      ::pread(proc_mem_fd, buffer.ptr + bytes_read, km.size() - bytes_read,
              km.start().as_int() + bytes_read);
  if (current_read == -1)
    return current_read;
  return bytes_read + current_read;
}

std::string checkpoints_index_file(const std::string& trace_dir) {
  return trace_dir + "/checkpoints";
}

static void write_map(const WriteVmConfig& cfg,
                      rr::pcp::KernelMapping::Builder builder,
                      const AddressSpace::Mapping& map) {
  LOG(debug) << "serializing " << map.map.str();
  builder.setStart(map.map.start().as_int());
  builder.setEnd(map.map.end().as_int());
  builder.setFsname(str_to_data(map.recorded_map.fsname()));
  builder.setDevice(map.map.device());
  builder.setInode(map.recorded_map.inode());
  builder.setProtection(map.map.prot());
  builder.setFlags(map.map.flags());
  // This will be interpreted as 0 on restore, since we create files for
  // individual mappings.
  builder.setOffset(map.map.file_offset_bytes());

  std::vector<uint64_t> pagemap_entries{};

  const auto page_count = map.map.size() / page_size();
  pagemap_entries.resize(page_count);

  const auto read_idx_start = (map.map.start().as_int() / page_size()) * 8;
  DEBUG_ASSERT(read_idx_start % 8 == 0);

  // walk the page map entries for mapping and determine on how we represent (or
  // not represent) it's data in the capnproto file
  auto entries_read_sz = ::pread(cfg.proc_pagemap_fd, pagemap_entries.data(),
                                 page_count * sizeof(uint64_t), read_idx_start);
  if (entries_read_sz == -1)
    FATAL() << "Failed to read page map";
  auto pages_present = 0;
  bool all_not_file_or_shared = true;
  for (auto pme : pagemap_entries) {
    if (PAGE_PRESENT(pme))
      pages_present++;
    // probably don't have to check _all_ of the mappings for this, since we
    // know the entire segment up front.
    if (PAGE_FILE_OR_SHARED_ANON(pme))
      all_not_file_or_shared = false;
  }

  // "guard segment": untouched, uninitialized memory, we don't write it's
  // contents
  if ((map.map.flags() & PRIVATE_ANON) == PRIVATE_ANON && pages_present == 0 &&
      map.map.prot() == PROT_NONE && all_not_file_or_shared) {
    builder.initMapType().setGuardSegment();
  } else {
    auto map_type = builder.initMapType();

    const auto pid = cfg.clone_leader->tid;
    const auto fname = file_name_of(map.map.fsname());
    // XXX when/if RR moves to c++20, use std::format.
    const auto len = std::snprintf(
        nullptr, 0, "%s/%d-%s-%p-%p", cfg.cp_data_dir, pid, fname.c_str(),
        (void*)map.map.start().as_int(), (void*)map.map.end().as_int());
    auto file = std::make_unique<char[]>(len + 1);
    if (map.map.fsname().empty()) {
      std::snprintf(file.get(), len, "%s/%d-%p-%p", cfg.cp_data_dir, pid,
                    (void*)map.map.start().as_int(),
                    (void*)map.map.end().as_int());
    } else {
      std::snprintf(file.get(), len, "%s/%d-%s-%p-%p", cfg.cp_data_dir, pid,
                    fname.c_str(), (void*)map.map.start().as_int(),
                    (void*)map.map.end().as_int());
    }
    ScopedFd f{ file.get(), O_EXCL | O_CREAT | O_RDWR, 0777 };
    if (!f.is_open())
      FILE_OP_FATAL(file) << "Couldn't open file";

    const auto sz = ::ftruncate(f, map.map.size());
    if (sz == -1)
      FILE_OP_FATAL(file) << "couldn't truncate file to size "
                          << map.map.size();

    auto bytes_read = 0ull;
    while (static_cast<size_t>(bytes_read) < map.map.size()) {
      const auto current_read = cfg.pread(bytes_read, map.map);
      if (current_read == -1)
        FILE_OP_FATAL(file) << " couldn't read contents of " << map.map.str();
      bytes_read = current_read;
    }

    ASSERT(cfg.clone_leader,
           static_cast<unsigned long>(bytes_read) == map.map.size())
        << " data read from /proc/" << cfg.clone_leader->tid
        << "/mem did not match kernel mapping metadata"
        << " read " << bytes_read << " expected: " << map.map.size() << " of "
        << map.map.str();

    const auto written_bytes = ::write(f, cfg.buffer.ptr, map.map.size());
    if (written_bytes == -1)
      FILE_OP_FATAL(file) << " couldn't write contents of " << map.map.str();

    const std::string data_fname{ file.get() };
    const auto contents_path = str_to_data(data_fname);
    if (map.flags == AddressSpace::Mapping::IS_RR_PAGE ||
        map.flags == AddressSpace::Mapping::IS_THREAD_LOCALS) {
      map_type.initRrPage().setContentsPath(contents_path);
    } else if (map.flags == AddressSpace::Mapping::IS_SYSCALLBUF) {
      map_type.initSyscallBuffer().setContentsPath(contents_path);
    } else if (map.emu_file) {
      // XXX simon(optimization): we should not need to write to shared
      // memory multiple times (once for each leader - just once?).
      auto shared_anon = map_type.initSharedAnon();
      const auto isSysVSegment =
          cfg.clone_leader->vm()->has_shm_at(map.map) ||
          cfg.clone_leader->vm()->has_shm_at(map.recorded_map);
      shared_anon.setContentsPath(contents_path);
      shared_anon.setIsSysVSegment(isSysVSegment);
    } else {
      if (map.map.fsname().empty() || map.map.is_stack() || map.map.is_heap()) {
        map_type.initPrivateAnon().setContentsPath(contents_path);
      } else {
        map_type.initFile().setContentsPath(contents_path);
      }
    }
  }
}

void write_vm(Task* clone_leader, rr::pcp::ProcessSpace::Builder builder,
              const std::string& checkpoint_data_dir) {
  LOG(debug) << "writing VM for " << clone_leader->rec_tid << " to "
             << checkpoint_data_dir;
  if (::mkdir(checkpoint_data_dir.c_str(), 0700) != 0) {
    LOG(info) << " directory " << checkpoint_data_dir << " already exists.";
  }

  std::vector<const AddressSpace::Mapping*> mappings;
  auto copy_buffer_size = 0ul;
  // any stack mapping will do. It has to be mapped first, mimicking
  // `process_execve` at restore
  const AddressSpace::Mapping* stack_mapping = nullptr;
  for (const auto& m : clone_leader->vm()->maps()) {
    // linux has exclusive control over this mapping.
    if (m.map.is_vsyscall()) {
      continue;
    }
    if (m.recorded_map.is_stack() && stack_mapping == nullptr) {
      stack_mapping = &m;
    } else {
      mappings.push_back(&m);
    }
    // largest mapping in the vm; use that as buffer size
    copy_buffer_size = std::max(copy_buffer_size, m.map.size());
  }

  ASSERT(clone_leader, !mappings.empty()) << "No mappings found to serialize";
  copy_buffer_size = ceil_page_size(copy_buffer_size);
  WriteVmConfig cfg{ clone_leader, checkpoint_data_dir.c_str(),
                     copy_buffer_size };

  auto kernel_mappings = builder.initVirtualAddressSpace(mappings.size() + 1);
  builder.setBreakpointFaultAddress(
      clone_leader->vm()->do_breakpoint_fault_addr().register_value());
  auto idx = 0;
  // write the/a stack mapping first. We're mimicking process_execve, therefore
  // we need a stack segment first

  write_map(cfg, kernel_mappings[idx++], *stack_mapping);
  for (auto m : mappings) {
    write_map(cfg, kernel_mappings[idx++], *m);
  }
}

// reads serialized map contents from |path|, mmaps a read buffer in the
// supervisor, then write its contents to mappping |km| in ReplayTask |t|.
void restore_map_contents(ReplayTask* t, const std::string& path,
                          const KernelMapping& km) {
  LOG(debug) << "restoring contents of " << km << " from " << path
             << " for task " << t->rec_tid;
  auto fd = ScopedFd(path.c_str(), O_RDONLY);
  ASSERT(t, fd.is_open()) << "Failed to open mapping contents file for "
                          << km.str() << " at " << path;

  auto addr = ::mmap(nullptr, km.size(), PROT_READ, MAP_PRIVATE, fd, 0);
  ASSERT(t, addr != MAP_FAILED)
      << "Could not load mapping contents of " << km.str() << " from " << path;

  bool write_ok = true;
  auto bytes_written = t->write_bytes_helper_no_notifications(
      km.start(), km.size(), addr, &write_ok);
  ASSERT(t, write_ok) << "Failed to restore contents of mapping from file for "
                      << km.str();
  ASSERT(t, static_cast<uint64_t>(bytes_written) == km.size())
      << "Failed to restore contents of mapping from file. Wrote "
      << bytes_written << "; expected " << km.size();
  if (::munmap(addr, km.size()) == -1) {
    FATAL() << "munmap failed for temporary buffer";
  }
}

void map_region_file(AutoRemoteSyscalls& remote, const KernelMapping& km,
                     const std::string& file_path) {
  struct stat real_file;
  std::string real_file_name;
  LOG(debug) << "directly mmap'ing " << km.size() << " bytes of " << file_path
             << " at offset " << HEX(km.file_offset_bytes()) << "(" << km.str()
             << ")";
  remote.finish_direct_mmap(km.start(), km.size(), km.prot(),
                            ((km.flags() & ~MAP_GROWSDOWN) | MAP_PRIVATE),
                            file_path.c_str(), O_RDONLY, 0, real_file,
                            real_file_name);
  remote.task()->vm()->map(remote.task(), km.start(), km.size(), km.prot(),
                           km.flags(), km.file_offset_bytes(), km.fsname(),
                           km.device(), km.inode(), nullptr, &km);
}

void map_private_anonymous(AutoRemoteSyscalls& remote,
                           const KernelMapping& km) {
  LOG(debug) << "map region no file: " << km.str();
  remote.infallible_mmap_syscall_if_alive(
      km.start(), km.size(), km.prot(),
      (km.flags() & ~MAP_GROWSDOWN) | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
  remote.task()->vm()->map(remote.task(), km.start(), km.size(), km.prot(),
                           km.flags(), km.file_offset_bytes(), km.fsname(),
                           km.device(), km.inode(), nullptr, &km);
}

Task::CapturedState reconstitute_captured_state(
    SupportedArch arch, const std::vector<CPUIDRecord>& cpuid_records,
    pcp::CapturedState::Reader reader) {
  Task::CapturedState res;
  res.ticks = reader.getTicks();
  auto register_raw = reader.getRegs().getRaw();
  res.regs = Registers{ arch };
  res.regs.restore_from_persistent_checkpoint(arch, register_raw.begin(),
                                              register_raw.size());

  auto raw = reader.getExtraRegs().getRaw();
  set_extra_regs_from_raw(arch, cpuid_records, raw, res.extra_regs);

  res.prname = data_to_str(reader.getPrname());
  res.fdtable_identity = reader.getFdtableIdentity();
  res.syscallbuf_child = reader.getSyscallbufChild();
  res.syscallbuf_size = reader.getSyscallbufSize();
  res.num_syscallbuf_bytes = reader.getNumSyscallbufBytes();
  res.preload_globals = reader.getPreloadGlobals();
  res.scratch_ptr = reader.getScratchPtr();
  res.scratch_size = reader.getScratchSize();
  res.top_of_stack = reader.getTopOfStack();
  auto rs = reader.getRseqState();
  res.rseq_state = std::make_unique<RseqState>(remote_ptr<void>(rs.getPtr()),
                                               rs.getAbortPrefixSignature());
  res.cloned_file_data_offset = reader.getClonedFileDataOffset();
  memcpy(res.thread_locals, reader.getThreadLocals().asBytes().begin(),
         PRELOAD_THREAD_LOCALS_SIZE);

  res.rec_tid = reader.getRecTid();
  res.own_namespace_rec_tid = reader.getOwnNamespaceRecTid();
  res.serial = reader.getSerial();
  res.tguid = ThreadGroupUid{ reader.getTguid().getTid(),
                              reader.getTguid().getSerial() };
  res.desched_fd_child = reader.getDeschedFdChild();
  res.cloned_file_data_fd_child = reader.getClonedFileDataFdChild();
  res.cloned_file_data_fname = data_to_str(reader.getClonedFileDataFname());
  res.wait_status = WaitStatus{ reader.getWaitStatus() };
  res.tls_register = reader.getTlsRegister();

  res.thread_areas = {};
  for (const auto& ta : reader.getThreadAreas()) {
    const X86Arch::user_desc item = *(X86Arch::user_desc*)ta.begin();
    res.thread_areas.push_back(item);
  }

  return res;
}

void init_scratch_memory(ReplayTask* t, const KernelMapping& km) {

  t->scratch_ptr = km.start();
  t->scratch_size = km.size();
  size_t sz = t->scratch_size;

  ASSERT(t, (km.prot() & (PROT_READ | PROT_WRITE)) == (PROT_READ | PROT_WRITE));
  ASSERT(t, (km.flags() & (MAP_PRIVATE | MAP_ANONYMOUS)) ==
                (MAP_PRIVATE | MAP_ANONYMOUS));

  {
    AutoRemoteSyscalls remote(t);
    remote.infallible_mmap_syscall_if_alive(t->scratch_ptr, sz, km.prot(),
                                            km.flags() | MAP_FIXED, -1, 0);
    t->vm()->map(t, t->scratch_ptr, sz, km.prot(), km.flags(), 0, std::string(),
                 KernelMapping::NO_DEVICE, KernelMapping::NO_INODE, nullptr,
                 &km);
  }
}

kj::Array<capnp::byte> prepare_user_desc(const X86Arch::user_desc& desc) {
  kj::Array<capnp::byte> data =
      kj::heapArray<capnp::byte>(sizeof(X86Arch::user_desc));
  memcpy(data.begin(), &desc, sizeof(X86Arch::user_desc)); // Copy raw bytes
  return data;
}

void write_capture_state(pcp::CapturedState::Builder& sb,
                         const Task::CapturedState& state) {
  sb.setTicks(state.ticks);
  sb.initRegs().setRaw(regs_to_raw(state.regs));
  sb.initExtraRegs().setRaw(extra_regs_to_raw(state.extra_regs));
  sb.setPrname(str_to_data(state.prname));
  sb.setFdtableIdentity(state.fdtable_identity);
  sb.setSyscallbufChild(state.syscallbuf_child.as_int());
  sb.setSyscallbufSize(state.syscallbuf_size);
  sb.setNumSyscallbufBytes(state.num_syscallbuf_bytes);
  sb.setPreloadGlobals(state.preload_globals.as_int());
  sb.setScratchPtr(state.scratch_ptr.as_int());
  sb.setScratchSize(state.scratch_size);
  sb.setTopOfStack(state.top_of_stack.as_int());
  auto rseq = sb.initRseqState();
  if (state.rseq_state) {
    rseq.setPtr(state.rseq_state->ptr.as_int());
    rseq.setAbortPrefixSignature(state.rseq_state->abort_prefix_signature);
  } else {
    rseq.setPtr(0);
    rseq.setAbortPrefixSignature(0);
  }

  sb.setClonedFileDataOffset(state.cloned_file_data_offset);
  auto tl = kj::ArrayPtr<const capnp::byte>(
      reinterpret_cast<const capnp::byte*>(state.thread_locals), 104);
  sb.setThreadLocals(tl);
  sb.setRecTid(state.rec_tid);
  sb.setOwnNamespaceRecTid(state.own_namespace_rec_tid);
  sb.setSerial(state.serial);
  auto tguid = sb.initTguid();
  tguid.setTid(state.tguid.tid());
  tguid.setSerial(state.tguid.serial());
  sb.setDeschedFdChild(state.desched_fd_child);
  sb.setClonedFileDataFdChild(state.cloned_file_data_fd_child);
  sb.setClonedFileDataFname(str_to_data(state.cloned_file_data_fname));
  sb.setWaitStatus(state.wait_status.get());
  sb.setTlsRegister(state.tls_register);
  auto thread_areas = sb.initThreadAreas(state.thread_areas.size());
  auto i = 0;
  for (const auto& ta : state.thread_areas) {
    thread_areas.set(
        i++, kj::ArrayPtr<const capnp::byte>(
                 reinterpret_cast<const capnp::byte*>(&ta), sizeof(ta)));
  }
}

void deserialize_fdtable(
    Task* leader, const rr::pcp::ProcessSpace::Reader& clone_leader_reader) {
  auto table = leader->fd_table();
  auto monitors = clone_leader_reader.getMonitors();
  for (auto m : monitors) {
    FileMonitor::Type t = (FileMonitor::Type)m.getType();
    auto fd = m.getFd();
    if (!table->is_monitoring(m.getFd())) {
      switch (t) {
        case FileMonitor::Base:
          FATAL() << "Can't add abstract type";
          break;
        case FileMonitor::MagicSaveData:
          table->add_monitor(leader, fd, new MagicSaveDataMonitor());
          break;
        case FileMonitor::Mmapped: {
          const auto mmap = m.getMmap();
          table->add_monitor(leader, fd,
                             new MmappedFileMonitor(mmap.getDead(),
                                                    mmap.getDevice(),
                                                    mmap.getInode()));
        } break;
        case FileMonitor::Preserve:
          table->add_monitor(leader, fd, new PreserveFileMonitor());
          break;
        case FileMonitor::ProcFd: {
          const auto p_fd = m.getProcFd();
          const auto tuid = TaskUid(p_fd.getTid(), p_fd.getSerial());
          table->add_monitor(leader, fd, new ProcFdDirMonitor(tuid));
          break;
        }
        case FileMonitor::ProcMem: {
          const auto pmem = m.getProcMem();
          table->add_monitor(
              leader, fd,
              new ProcMemMonitor(AddressSpaceUid(
                  pmem.getTid(), pmem.getSerial(), pmem.getExecCount())));
          break;
        }
        case FileMonitor::Stdio:
          table->add_monitor(leader, fd, new StdioMonitor(m.getStdio()));
          break;
        case FileMonitor::VirtualPerfCounter:
          FATAL() << "VirtualPerCounter Monitor deserializing unimplemented!\n";
          break;
        case FileMonitor::NonvirtualPerfCounter:
          table->add_monitor(leader, fd, new NonvirtualPerfCounterMonitor());
          break;
        case FileMonitor::SysCpu:
          table->add_monitor(leader, fd, new SysCpuMonitor(leader, ""));
          break;
        case FileMonitor::ProcStat:
          table->add_monitor(
              leader, fd,
              new ProcStatMonitor(leader, data_to_str(m.getProcStat())));
          break;
        case FileMonitor::RRPage:
          table->add_monitor(leader, fd, new RRPageMonitor());
          break;
        case FileMonitor::ODirect:
          table->add_monitor(leader, fd, new ODirectFileMonitor());
          break;
        case FileMonitor::BpfMap:
          table->add_monitor(leader, fd,
                             new BpfMapMonitor(m.getBpf().getKeySize(),
                                               m.getBpf().getValueSize()));
          break;
        case FileMonitor::PidFd:
          FATAL() << "PidFd not supported to be serialized yet";
          break;
      }
    }
  }
}

} // namespace rr