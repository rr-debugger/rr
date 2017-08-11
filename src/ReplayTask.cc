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
                       uint32_t serial, SupportedArch a)
    : Task(session, _tid, _rec_tid, serial, a) {}

ReplaySession& ReplayTask::session() const {
  return *Task::session().as_replay();
}

TraceReader& ReplayTask::trace_reader() const {
  return session().trace_reader();
}

template <typename Arch>
void ReplayTask::init_buffers_arch(remote_ptr<void> map_hint) {
  apply_all_data_records_from_trace();

  AutoRemoteSyscalls remote(this);

  remote_ptr<rrcall_init_buffers_params<Arch>> child_args = regs().arg1();
  auto args = read_mem(child_args);

  if (args.syscallbuf_ptr) {
    syscallbuf_size = args.syscallbuf_size;
    init_syscall_buffer(remote, map_hint);
    desched_fd_child = args.desched_counter_fd;
    // Prevent the child from closing this fd
    fds->add_monitor(desched_fd_child, new PreserveFileMonitor());

    // Skip mmap record. It exists mainly to inform non-replay code
    // (e.g. RemixModule) that this memory will be mapped.
    trace_reader().read_mapped_region();

    if (args.cloned_file_data_fd >= 0) {
      cloned_file_data_fd_child = args.cloned_file_data_fd;
      string clone_file_name = trace_reader().file_data_clone_file_name(tuid());
      AutoRestoreMem name(remote, clone_file_name.c_str());
      int fd = remote.infallible_syscall(syscall_number_for_openat(arch()),
                                         RR_RESERVED_ROOT_DIR_FD, name.get(),
                                         O_RDONLY | O_CLOEXEC);
      if (fd != cloned_file_data_fd_child) {
        long ret =
            remote.infallible_syscall(syscall_number_for_dup3(arch()), fd,
                                      cloned_file_data_fd_child, O_CLOEXEC);
        ASSERT(this, ret == cloned_file_data_fd_child);
        remote.infallible_syscall(syscall_number_for_close(arch()), fd);
      }
      fds->add_monitor(cloned_file_data_fd_child, new PreserveFileMonitor());
    }
  }

  remote.regs().set_syscall_result(syscallbuf_child);
}

void ReplayTask::init_buffers(remote_ptr<void> map_hint) {
  RR_ARCH_FUNCTION(init_buffers_arch, arch(), map_hint);
}

void ReplayTask::post_exec_syscall(const string& replay_exe) {
  Task::post_exec(replay_exe);

  // Perform post-exec-syscall tasks now (e.g. opening mem_fd) before we
  // switch registers. This lets us perform AutoRemoteSyscalls using the
  // regular stack instead of having to search the address space for usable
  // pages (which is error prone, e.g. if we happen to find the scratch space
  // allocated by an rr recorder under which we're running).
  Task::post_exec_syscall();

  // Delay setting the replay_regs until here so the original registers
  // are set while we populate AddressSpace. We need that for the kernel
  // to identify the original stack region correctly.
  set_regs(current_trace_frame().regs());
  extra_registers = current_trace_frame().extra_regs();
  ASSERT(this, !extra_registers.empty());
  set_extra_regs(extra_registers);
}

void ReplayTask::validate_regs(uint32_t flags) {
  /* don't validate anything before execve is done as the actual
   * process did not start prior to this point */
  if (!session().done_initial_exec()) {
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
  Registers::compare_register_files(this, "replaying", regs(), "recorded",
                                    rec_regs, BAIL_ON_MISMATCH);
}

const TraceFrame& ReplayTask::current_trace_frame() {
  return session().current_trace_frame();
}

FrameTime ReplayTask::current_frame_time() {
  return current_trace_frame().time();
}

ssize_t ReplayTask::set_data_from_trace() {
  auto buf = trace_reader().read_raw_data();
  if (!buf.addr.is_null() && buf.data.size() > 0) {
    auto t = session().find_task(buf.rec_tid);
    t->write_bytes_helper(buf.addr, buf.data.size(), buf.data.data());
    t->vm()->maybe_update_breakpoints(t, buf.addr.cast<uint8_t>(),
                                      buf.data.size());
  }
  return buf.data.size();
}

void ReplayTask::apply_all_data_records_from_trace() {
  TraceReader::RawData buf;
  while (trace_reader().read_raw_data_for_frame(buf)) {
    if (!buf.addr.is_null() && buf.data.size() > 0) {
      auto t = session().find_task(buf.rec_tid);
      t->write_bytes_helper(buf.addr, buf.data.size(), buf.data.data());
      t->vm()->maybe_update_breakpoints(t, buf.addr.cast<uint8_t>(),
                                        buf.data.size());
    }
  }
}

void ReplayTask::set_return_value_from_trace() {
  Registers r = regs();
  r.set_syscall_result(current_trace_frame().regs().syscall_result());
  // In some cases (e.g. syscalls forced to return an error by tracee
  // seccomp filters) we need to emulate a change to the original_syscallno
  // (to -1 in that case).
  r.set_original_syscallno(current_trace_frame().regs().original_syscallno());
  set_regs(r);
}

void ReplayTask::set_real_tid_and_update_serial(pid_t tid) {
  hpc.set_tid(tid);
  this->tid = tid;
  serial = session().next_task_serial();
}

} // namespace rr
