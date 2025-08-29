/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "ReplayTask.h"

#include "AutoRemoteSyscalls.h"
#include "PreserveFileMonitor.h"
#include "ReplaySession.h"
#include "log.h"
#include "rr/rr.h"

using namespace std;

namespace rr {

ReplayTask::ReplayTask(ReplaySession& session, pid_t _tid, pid_t _rec_tid,
                       uint32_t serial, SupportedArch a,
                       const std::string& name)
    : Task(session, _tid, _rec_tid, serial, a),
      name_(name),
      seen_sched_in_syscallbuf_syscall_hook(false)
{}

ReplaySession& ReplayTask::session() const {
  return *Task::session().as_replay();
}

TraceReader& ReplayTask::trace_reader() const {
  return session().trace_reader();
}

template <typename Arch>
void ReplayTask::init_buffers_arch() {
  apply_all_data_records_from_trace();

  AutoRemoteSyscalls remote(this);

  remote_ptr<rrcall_init_buffers_params<Arch>> child_args = regs().arg1();
  auto args = read_mem(child_args);

  if (args.syscallbuf_ptr) {
    syscallbuf_size = args.syscallbuf_size;
    init_syscall_buffer(remote, args.syscallbuf_ptr);
    desched_fd_child = args.desched_counter_fd;
    // Prevent the child from closing this fd
    fds->add_monitor(this, desched_fd_child, new PreserveFileMonitor());

    // Skip mmap record. It exists mainly to inform non-replay code
    // (e.g. RemixModule) that this memory will be mapped.
    trace_reader().read_mapped_region();

    if (args.cloned_file_data_fd >= 0) {
      cloned_file_data_fd_child = args.cloned_file_data_fd;
      cloned_file_data_fname = trace_reader().file_data_clone_file_name(tuid());
      ScopedFd clone_file(cloned_file_data_fname.c_str(), O_RDONLY);
      ASSERT(this, clone_file.is_open());
      remote.infallible_send_fd_dup(clone_file, cloned_file_data_fd_child, O_CLOEXEC);
      fds->add_monitor(this, cloned_file_data_fd_child, new PreserveFileMonitor());
    }
  }

  remote.regs().set_syscall_result(syscallbuf_child);
}

void ReplayTask::init_buffers() {
  RR_ARCH_FUNCTION(init_buffers_arch, arch());
}

void ReplayTask::post_exec_syscall(const string& replay_exe, const string& original_replay_exe) {
  Task::post_exec(replay_exe);

  // Perform post-exec-syscall tasks now (e.g. opening mem_fd) before we
  // switch registers. This lets us perform AutoRemoteSyscalls using the
  // regular stack instead of having to search the address space for usable
  // pages (which is error prone, e.g. if we happen to find the scratch space
  // allocated by an rr recorder under which we're running).
  Task::post_exec_syscall(original_replay_exe);

  // Delay setting the replay_regs until here so the original registers
  // are set while we populate AddressSpace. We need that for the kernel
  // to identify the original stack region correctly.
  set_regs(current_trace_frame().regs());
  extra_registers = current_trace_frame().extra_regs();
  ASSERT(this, !extra_registers.empty());
  set_extra_regs(extra_registers);
}

void ReplayTask::set_name(AutoRemoteSyscalls& remote, const std::string& name) {
  name_ = name;
  Task::set_name(remote, "rr:" + name);
}

void ReplayTask::did_prctl_set_prname(remote_ptr<void> child_addr) {
  char buf[16];
  // The null-terminated name might start within the last 16 bytes of a memory
  // mapping.
  ssize_t bytes = read_bytes_fallible(child_addr, sizeof(buf), buf);
  // If there was no readable data then this shouldn't be called
  ASSERT(this, bytes > 0);
  // Make sure the final byte is null if the string needed to be truncated
  buf[bytes - 1] = 0;
  AutoRemoteSyscalls remote(this);
  set_name(remote, buf);
}

void ReplayTask::validate_regs(uint32_t flags) {
  /* don't validate anything before execve is done as the actual
   * process did not start prior to this point */
  if (!session().done_initial_exec()) {
    return;
  }
  if (seen_sched_in_syscallbuf_syscall_hook) {
    /* Registers may diverge here */
    return;
  }

  Registers rec_regs = current_trace_frame().regs();

  if (flags & IGNORE_ESI) {
    if (regs().arg4() != rec_regs.arg4()) {
      LOG(warn) << "Probably saw kernel bug mutating $esi across pread/write64 "
                   "call: recorded:"
                << HEX(rec_regs.arg4()) << "; replaying:" << regs().arg4()
                << ".  Fudging registers.";
      rec_regs.set_arg4(regs().arg4());
    }
  }

  /* TODO: add perf counter validations (hw int, page faults, insts) */
  Registers::Comparison comparison = regs().compare_with(rec_regs);
  ASSERT(this, !comparison.mismatch_count) << "Mismatched registers, replay vs rec: "
      << comparison;
}

const TraceFrame& ReplayTask::current_trace_frame() const {
  return session().current_trace_frame();
}

FrameTime ReplayTask::current_frame_time() const {
  return current_trace_frame().time();
}

// Returns number of bytes written (including holes)
static size_t write_data_with_holes(ReplayTask* t,
                                    const TraceReader::RawDataWithHoles& buf) {
  unique_ptr<AutoRemoteSyscalls> remote;
  size_t data_offset = 0;
  size_t addr_offset = 0;
  auto holes_iter = buf.holes.begin();
  while (data_offset < buf.data.size() || holes_iter != buf.holes.end()) {
    if (holes_iter != buf.holes.end() && holes_iter->offset == addr_offset) {
      t->write_zeroes(&remote, buf.addr + addr_offset, holes_iter->size);
      addr_offset += holes_iter->size;
      ++holes_iter;
      continue;
    }
    size_t data_end = buf.data.size();
    if (holes_iter != buf.holes.end()) {
      data_end = data_offset + holes_iter->offset - addr_offset;
    }
    bool ok = true;
    ssize_t nwritten = t->write_bytes_helper(buf.addr + addr_offset, data_end - data_offset,
                                             buf.data.data() + data_offset,&ok);

    ASSERT(t, ok || buf.size_validation == MemWriteSizeValidation::CONSERVATIVE)
        << "Should have written " << buf.data.size() << " bytes to " << (buf.addr + addr_offset)
        << ", but only wrote " << nwritten;

    addr_offset += data_end - data_offset;
    data_offset = data_end;
  }
  return addr_offset;
}

void ReplayTask::apply_data_record_from_trace() {
  TraceReader::RawDataWithHoles buf;
  bool ok = trace_reader().read_raw_data_for_frame_with_holes(buf);
  ASSERT(this, ok);
  if (buf.addr.is_null()) {
    return;
  }
  auto t = session().find_task(buf.rec_tid);
  size_t size = write_data_with_holes(t, buf);
  t->vm()->maybe_update_breakpoints(t, buf.addr.cast<uint8_t>(), size);
}

void ReplayTask::apply_all_data_records_from_trace() {
  TraceReader::RawDataWithHoles buf;
  while (trace_reader().read_raw_data_for_frame_with_holes(buf)) {
    if (buf.addr.is_null()) {
      continue;
    }
    auto t = session().find_task(buf.rec_tid);
    size_t size = write_data_with_holes(t, buf);
    t->vm()->maybe_update_breakpoints(t, buf.addr.cast<uint8_t>(), size);
  }
}

void ReplayTask::set_return_value_from_trace() {
  Registers r = regs();
  r.set_syscall_result(current_trace_frame().regs().syscall_result());
  // In some cases (e.g. syscalls forced to return an error by tracee
  // seccomp filters) we need to emulate a change to the original_syscallno
  // (to -1 in that case).
  r.set_original_syscallno(current_trace_frame().regs().original_syscallno());
  if (r.original_syscallno() == session().syscall_number_for_rrcall_rdtsc()) {
    ASSERT(this, is_x86ish(arch()));
    // EAX has been set via set_syscall_result above
    r.set_dx(current_trace_frame().regs().dx());
  }
  set_regs(r);
}

void ReplayTask::set_real_tid_and_update_serial(pid_t tid) {
  hpc.set_tid(tid);
  this->tid = tid;
  serial = session().next_task_serial();
}

const ExtraRegisters& ReplayTask::extra_regs() {
  if (!extra_regs_fallible()) {
    ASSERT(this, false) << "Can't find task for infallible extra_regs";
  }
  return extra_registers;
}

bool ReplayTask::post_vm_clone(CloneReason reason, int flags, Task* origin) {
  if (Task::post_vm_clone(reason, flags, origin) &&
      reason == TRACEE_CLONE &&
      trace_reader().preload_thread_locals_recorded()) {
    // Consume the mapping.
    TraceReader::MappedData data;
    KernelMapping km = trace_reader().read_mapped_region(&data);
    ASSERT(this, km.start() == AddressSpace::preload_thread_locals_start() &&
           km.size() == page_size());
    return true;
  }

  return false;
}

} // namespace rr
