/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef _GNU_SOURCE
// For utsname::domainname
#define _GNU_SOURCE 1
#endif

#include "TraceStream.h"

#include <capnp/message.h>
#include <capnp/serialize-packed.h>
#include <inttypes.h>
#include <limits.h>
#include <sched.h>
#include <sys/file.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <dirent.h>

#include <algorithm>
#include <fstream>
#include <sstream>
#include <string>

#include "AddressSpace.h"
#include "AutoRemoteSyscalls.h"
#include "Event.h"
#include "RecordSession.h"
#include "RecordTask.h"
#include "TaskishUid.h"
#include "core.h"
#include "kernel_abi.h"
#include "kernel_metadata.h"
#include "kernel_supplement.h"
#include "log.h"
#include "preload/preload_interface.h"
#include "rr_trace.capnp.h"
#include "util.h"

#include "rr/rr.h"

using namespace std;
using namespace capnp;

namespace rr {

//
// This represents the format and layout of recorded traces.  This
// version number doesn't track the rr version number, because changes
// to the trace format will be rare.
//
// We don't plan to ever change this again. Instead, we use CapnpProto
// to define the trace format in an extensible way (see rr_trace.capnp).
//
#define TRACE_VERSION 85

struct SubstreamData {
  const char* name;
  size_t block_size;
  int threads;
};

static SubstreamData substreams[TraceStream::SUBSTREAM_COUNT] = {
  { "events", 1024 * 1024, 1 },
  { "data", 1024 * 1024, 0 },
  { "mmaps", 64 * 1024, 1 },
  { "tasks", 64 * 1024, 1 },
};

static const SubstreamData& substream(TraceStream::Substream s) {
  if (!substreams[TraceStream::RAW_DATA].threads) {
    substreams[TraceStream::RAW_DATA].threads = min(8, get_num_cpus());
  }
  return substreams[s];
}

static TraceStream::Substream operator++(TraceStream::Substream& s) {
  s = (TraceStream::Substream)(s + 1);
  return s;
}

static bool dir_exists(const string& dir) {
  struct stat dummy;
  return !dir.empty() && stat(dir.c_str(), &dummy) == 0;
}

static string default_rr_trace_dir() {
  static string cached_dir;

  if (!cached_dir.empty()) {
    return cached_dir;
  }

  string dot_dir;
  const char* home = getenv("HOME");
  if (home) {
    dot_dir = string(home) + "/.rr";
  }
  string xdg_dir;
  const char* xdg_data_home = getenv("XDG_DATA_HOME");
  if (xdg_data_home) {
    xdg_dir = string(xdg_data_home) + "/rr";
  } else if (home) {
    xdg_dir = string(home) + "/.local/share/rr";
  }

  // If XDG dir does not exist but ~/.rr does, prefer ~/.rr for backwards
  // compatibility.
  if (dir_exists(xdg_dir)) {
    cached_dir = xdg_dir;
  } else if (dir_exists(dot_dir)) {
    cached_dir = dot_dir;
  } else if (!xdg_dir.empty()) {
    cached_dir = xdg_dir;
  } else {
    cached_dir = "/tmp/rr";
  }

  return cached_dir;
}

string trace_save_dir() {
  const char* output_dir = getenv("_RR_TRACE_DIR");
  return output_dir ? output_dir : default_rr_trace_dir();
}

string latest_trace_symlink() {
  return trace_save_dir() + "/latest-trace";
}

string resolve_trace_name(const string& trace_name)
{
  if (trace_name.empty()) {
    return latest_trace_symlink();
  }

  // Single-component paths are looked up first in the current directory, next
  // in the default trace dir.

  if (trace_name.find('/') == string::npos) {
    if (dir_exists(trace_name)) {
      return trace_name;
    }

    string resolved_trace_name = trace_save_dir() + "/" + trace_name;
    if (dir_exists(resolved_trace_name)) {
      return resolved_trace_name;
    }
  }

  return trace_name;
}

class CompressedWriterOutputStream : public kj::OutputStream {
public:
  CompressedWriterOutputStream(CompressedWriter& writer) : writer(writer) {}
  virtual ~CompressedWriterOutputStream() {}

  virtual void write(const void* buffer, size_t size) {
    writer.write(buffer, size);
  }

private:
  CompressedWriter& writer;
};

struct IOException {};

class CompressedReaderInputStream : public kj::BufferedInputStream {
public:
  CompressedReaderInputStream(CompressedReader& reader) : reader(reader) {}
  virtual ~CompressedReaderInputStream() {}

  virtual size_t tryRead(void* buffer, size_t, size_t maxBytes) {
    if (!reader.read(buffer, maxBytes)) {
      throw IOException();
    }
    return maxBytes;
  }
  virtual void skip(size_t bytes) {
    reader.skip(bytes);
  }
  virtual kj::ArrayPtr<const capnp::byte> tryGetReadBuffer() {
    const uint8_t* p;
    size_t size;
    if (!reader.get_buffer(&p, &size)) {
      throw IOException();
    }
    return kj::ArrayPtr<const capnp::byte>(p, size);
  }

private:
  CompressedReader& reader;
};

TraceStream::TraceStream(const string& trace_dir, FrameTime initial_time)
    : trace_dir(real_path(trace_dir)),
      bind_to_cpu(-1),
      global_time(initial_time)
   {}

string TraceStream::file_data_clone_file_name(const TaskUid& tuid) {
  stringstream ss;
  ss << trace_dir << "/cloned_data_" << tuid.tid() << "_" << tuid.serial();
  return ss.str();
}

string TraceStream::path(Substream s) {
  return trace_dir + "/" + substream(s).name;
}

size_t TraceStream::mmaps_block_size() { return substreams[MMAPS].block_size; }

bool TraceWriter::good() const {
  for (auto& w : writers) {
    if (!w->good()) {
      return false;
    }
  }
  return true;
}

bool TraceReader::good() const {
  for (auto& r : readers) {
    if (!r->good()) {
      return false;
    }
  }
  return true;
}

static kj::ArrayPtr<const capnp::byte> str_to_data(const string& str) {
  return kj::ArrayPtr<const capnp::byte>(
      reinterpret_cast<const capnp::byte*>(str.data()), str.size());
}

static string data_to_str(const kj::ArrayPtr<const capnp::byte>& data) {
  if (!data.begin()) {
    return string();
  }
  if (memchr(data.begin(), 0, data.size())) {
    FATAL() << "Invalid string: contains null character";
  }
  return string(reinterpret_cast<const char*>(data.begin()), data.size());
}

static trace::Arch to_trace_arch(SupportedArch arch) {
  switch (arch) {
    case x86:
      return trace::Arch::X86;
    case x86_64:
      return trace::Arch::X8664;
    case aarch64:
      return trace::Arch::AARCH64;
    default:
      FATAL() << "Unknown arch";
      return trace::Arch::X86;
  }
}

static trace::CpuTriState to_tristate(bool value) {
  return value ? trace::CpuTriState::KNOWN_TRUE : trace::CpuTriState::KNOWN_FALSE;
}

static SupportedArch from_trace_arch(trace::Arch arch) {
  switch (arch) {
    case trace::Arch::X86:
      return x86;
    case trace::Arch::X8664:
      return x86_64;
    case trace::Arch::AARCH64:
      return aarch64;
    default:
      FATAL() << "Unknown arch";
      return x86;
  }
}

static trace::SignalDisposition to_trace_disposition(
    SignalResolvedDisposition disposition) {
  switch (disposition) {
    case DISPOSITION_FATAL:
      return trace::SignalDisposition::FATAL;
    case DISPOSITION_IGNORED:
      return trace::SignalDisposition::IGNORED;
    case DISPOSITION_USER_HANDLER:
      return trace::SignalDisposition::USER_HANDLER;
    default:
      FATAL() << "Unknown disposition";
      return trace::SignalDisposition::FATAL;
  }
}

static SignalResolvedDisposition from_trace_disposition(
    trace::SignalDisposition disposition) {
  switch (disposition) {
    case trace::SignalDisposition::FATAL:
      return DISPOSITION_FATAL;
    case trace::SignalDisposition::IGNORED:
      return DISPOSITION_IGNORED;
    case trace::SignalDisposition::USER_HANDLER:
      return DISPOSITION_USER_HANDLER;
    default:
      FATAL() << "Unknown disposition";
      return DISPOSITION_FATAL;
  }
}

static trace::SyscallState to_trace_syscall_state(SyscallState state) {
  switch (state) {
    case ENTERING_SYSCALL_PTRACE:
      return trace::SyscallState::ENTERING_PTRACE;
    case ENTERING_SYSCALL:
      return trace::SyscallState::ENTERING;
    case EXITING_SYSCALL:
      return trace::SyscallState::EXITING;
    default:
      FATAL() << "Unknown syscall state";
      return trace::SyscallState::ENTERING;
  }
}

static SyscallState from_trace_syscall_state(trace::SyscallState state) {
  switch (state) {
    case trace::SyscallState::ENTERING_PTRACE:
      return ENTERING_SYSCALL_PTRACE;
    case trace::SyscallState::ENTERING:
      return ENTERING_SYSCALL;
    case trace::SyscallState::EXITING:
      return EXITING_SYSCALL;
    default:
      FATAL() << "Unknown syscall state";
      return ENTERING_SYSCALL;
  }
}

static void to_trace_signal(trace::Signal::Builder signal, const Event& ev) {
  const SignalEvent& sig_ev = ev.Signal();
  signal.setSiginfoArch(to_trace_arch(NativeArch::arch()));
  signal.setSiginfo(
      Data::Reader(reinterpret_cast<const uint8_t*>(&sig_ev.siginfo),
                   sizeof(sig_ev.siginfo)));
  signal.setDeterministic(sig_ev.deterministic == DETERMINISTIC_SIG);
  signal.setDisposition(to_trace_disposition(sig_ev.disposition));
}

static Event from_trace_signal(EventType type, trace::Signal::Reader signal) {
  union {
    NativeArch::siginfo_t native_siginfo;
    siginfo_t system_siginfo;
  } si;
  auto siginfo = signal.getSiginfo();
  si.native_siginfo = convert_to_native_siginfo(from_trace_arch(signal.getSiginfoArch()),
      siginfo.begin(), siginfo.size());
  return Event(type,
               SignalEvent(si.system_siginfo,
                           signal.getDeterministic() ? DETERMINISTIC_SIG
                                                     : NONDETERMINISTIC_SIG,
                           from_trace_disposition(signal.getDisposition())));
}

static trace::TicksSemantics to_trace_ticks_semantics(TicksSemantics semantics) {
  switch (semantics) {
    case TICKS_RETIRED_CONDITIONAL_BRANCHES:
      return trace::TicksSemantics::RETIRED_CONDITIONAL_BRANCHES;
    case TICKS_TAKEN_BRANCHES:
      return trace::TicksSemantics::TAKEN_BRANCHES;
    default:
      FATAL() << "Unknown ticks semantics";
      return trace::TicksSemantics::RETIRED_CONDITIONAL_BRANCHES;
  }
}

static TicksSemantics from_trace_ticks_semantics(trace::TicksSemantics semantics) {
  switch (semantics) {
    case trace::TicksSemantics::RETIRED_CONDITIONAL_BRANCHES:
      return TICKS_RETIRED_CONDITIONAL_BRANCHES;
    case trace::TicksSemantics::TAKEN_BRANCHES:
      return TICKS_TAKEN_BRANCHES;
    default:
      FATAL() << "Unknown ticks semantics";
      return TICKS_RETIRED_CONDITIONAL_BRANCHES;
  }
}

static pid_t i32_to_tid(int tid) {
  if (tid <= 0) {
    FATAL() << "Invalid tid";
  }
  return tid;
}

static int check_fd(int fd) {
  if (fd < 0) {
    FATAL() << "Invalid fd";
  }
  return fd;
}

// 8-byte words
static const size_t reasonable_frame_message_words = 64;

void TraceWriter::write_frame(RecordTask* t, const Event& ev,
                              const Registers* registers,
                              const ExtraRegisters* extra_registers) {
  // Use an on-stack first segment that should be adequate for most cases. A
  // simple syscall event takes 320 bytes currently. The default Capnproto
  // implementation does a calloc(8192) for the first segment.
  word buf[reasonable_frame_message_words] = {};
  MallocMessageBuilder frame_msg(buf);
  trace::Frame::Builder frame = frame_msg.initRoot<trace::Frame>();

  frame.setTid(t->tid);
  frame.setTicks(t->tick_count());
  frame.setMonotonicSec(monotonic_now_sec());
  frame.setInSyscallbufSyscallHook(0);
  auto mem_writes = frame.initMemWrites(raw_recs.size());
  for (size_t i = 0; i < raw_recs.size(); ++i) {
    auto w = mem_writes[i];
    auto& r = raw_recs[i];
    w.setTid(r.rec_tid);
    w.setAddr(r.addr.as_int());
    w.setSize(r.size);
    w.setSizeIsConservative(r.size_validation == MemWriteSizeValidation::CONSERVATIVE);
    auto holes = w.initHoles(r.holes.size());
    for (size_t j = 0; j < r.holes.size(); ++j) {
      holes[j].setOffset(r.holes[j].offset);
      holes[j].setSize(r.holes[j].size);
    }
  }
  raw_recs.clear();
  frame.setArch(to_trace_arch(t->arch()));
  if (registers) {
    // Avoid dynamic allocation and copy
    auto raw_regs = registers->get_regs_for_trace();
    frame.initRegisters().setRaw(Data::Reader(raw_regs.data, raw_regs.size));
  }
  if (extra_registers) {
    frame.initExtraRegisters().setRaw(Data::Reader(
        extra_registers->data_bytes(), extra_registers->data_size()));
  }

  auto event = frame.initEvent();
  switch (ev.type()) {
    case EV_INSTRUCTION_TRAP:
      event.setInstructionTrap(Void());
      break;
    case EV_PATCH_SYSCALL:
      if (ev.PatchSyscall().patch_trapping_instruction) {
        event.setPatchTrappingInstruction(Void());
      } else if (ev.PatchSyscall().patch_vsyscall) {
        event.setPatchVsyscall(Void());
      } else if (ev.PatchSyscall().patch_after_syscall) {
        event.setPatchAfterSyscall(Void());
      } else {
        event.setPatchSyscall(Void());
      }
      break;
    case EV_SYSCALLBUF_ABORT_COMMIT:
      event.setSyscallbufAbortCommit(Void());
      break;
    case EV_SYSCALLBUF_RESET:
      event.setSyscallbufReset(Void());
      break;
    case EV_SCHED:
      frame.setInSyscallbufSyscallHook(ev.Sched().in_syscallbuf_syscall_hook.register_value());
      event.setSched(Void());
      break;
    case EV_GROW_MAP:
      event.setGrowMap(Void());
      break;
    case EV_SIGNAL:
      to_trace_signal(event.initSignal(), ev);
      break;
    case EV_SIGNAL_DELIVERY:
      to_trace_signal(event.initSignalDelivery(), ev);
      break;
    case EV_SIGNAL_HANDLER:
      to_trace_signal(event.initSignalHandler(), ev);
      break;
    case EV_EXIT:
      event.setExit(Void());
      break;
    case EV_SYSCALLBUF_FLUSH: {
      const SyscallbufFlushEvent& e = ev.SyscallbufFlush();
      event.initSyscallbufFlush().setMprotectRecords(Data::Reader(
          reinterpret_cast<const uint8_t*>(e.mprotect_records.data()),
          e.mprotect_records.size() * sizeof(mprotect_record)));
      break;
    }
    case EV_SYSCALL: {
      const SyscallEvent& e = ev.Syscall();
      auto syscall = event.initSyscall();
      syscall.setArch(to_trace_arch(e.arch()));
      syscall.setNumber(e.is_restart
                            ? syscall_number_for_restart_syscall(t->arch())
                            : e.number);
      syscall.setState(to_trace_syscall_state(e.state));
      syscall.setFailedDuringPreparation(e.failed_during_preparation);
      auto data = syscall.initExtra();
      if (e.write_offset >= 0) {
        data.setWriteOffset(e.write_offset);
      }
      if (!e.exec_fds_to_close.empty()) {
        data.setExecFdsToClose(kj::ArrayPtr<const int>(
            e.exec_fds_to_close.data(), e.exec_fds_to_close.size()));
      }
      if (!e.opened.empty()) {
        auto open = data.initOpenedFds(e.opened.size());
        for (size_t i = 0; i < e.opened.size(); ++i) {
          auto o = open[i];
          auto opened = e.opened[i];
          o.setFd(opened.fd);
          o.setPath(str_to_data(opened.path));
          o.setDevice(opened.device);
          o.setInode(opened.inode);
        }
      }
      if (e.socket_addrs) {
        auto addrs = data.initSocketAddrs();
        auto localAddr = (*e.socket_addrs.get())[0];
        auto remoteAddr = (*e.socket_addrs.get())[1];
        addrs.setLocalAddr(Data::Reader(reinterpret_cast<uint8_t*>(&localAddr), sizeof(localAddr)));
        addrs.setRemoteAddr(Data::Reader(reinterpret_cast<uint8_t*>(&remoteAddr), sizeof(remoteAddr)));
      }
      if (!e.madvise_ranges.empty()) {
        auto ranges = data.initMadviseRanges(e.madvise_ranges.size());
        for (size_t i = 0; i < e.madvise_ranges.size(); ++i) {
          auto r = ranges[i];
          auto mr = e.madvise_ranges[i];
          r.setStart(mr.start().as_int());
          r.setEnd(mr.end().as_int());
        }
      }
      break;
    }
    default:
      FATAL() << "Event type not recordable";
      break;
  }

  try {
    auto& events = writer(EVENTS);
    CompressedWriterOutputStream stream(events);
    writePackedMessage(stream, frame_msg);
  } catch (...) {
    FATAL() << "Unable to write events";
  }

  tick_time();
}

TraceFrame TraceReader::read_frame(FrameTime skip_before) {
  auto& events = reader(EVENTS);
  word buf[reasonable_frame_message_words];
  CompressedReaderInputStream stream(events);
  PackedMessageReader frame_msg(stream, ReaderOptions(), buf);
  tick_time();
  TraceFrame ret;
  ret.global_time = time();

  trace::Frame::Reader frame = frame_msg.getRoot<trace::Frame>();

  auto mem_writes = frame.getMemWrites();
  raw_recs.resize(mem_writes.size());
  for (size_t i = 0; i < raw_recs.size(); ++i) {
    // Build list in reverse order so we can efficiently pull records from it
    auto w = mem_writes[raw_recs.size() - 1 - i];
    auto holes = w.getHoles();
    vector<WriteHole> h;
    h.resize(holes.size());
    for (size_t j = 0; j < h.size(); ++j) {
      const auto& hole = holes[j];
      h[j] = { hole.getOffset(), hole.getSize() };
    }
    raw_recs[i] = { w.getAddr(), (size_t)w.getSize(), i32_to_tid(w.getTid()), h,
                    w.getSizeIsConservative() ? MemWriteSizeValidation::CONSERVATIVE : MemWriteSizeValidation::EXACT };
  }

  if (ret.global_time < skip_before) {
    return ret;
  }

  ret.tid_ = i32_to_tid(frame.getTid());
  ret.ticks_ = frame.getTicks();
  if (ret.ticks_ < 0) {
    FATAL() << "Invalid ticks value";
  }
  monotonic_time_ = ret.monotonic_time_ = frame.getMonotonicSec();

  SupportedArch arch = from_trace_arch(frame.getArch());
  ret.recorded_regs.set_arch(arch);
  auto reg_data = frame.getRegisters().getRaw();
  if (reg_data.size()) {
    ret.recorded_regs.set_from_trace(arch, reg_data.begin(),
                                     reg_data.size());
  }
  auto extra_reg_data = frame.getExtraRegisters().getRaw();
  if (extra_reg_data.size()) {
    ExtraRegisters::Format fmt;
    switch (arch) {
      default:
        FATAL() << "Unknown architecture";
        RR_FALLTHROUGH;
      case x86:
      case x86_64:
        fmt = ExtraRegisters::XSAVE;
        break;
      case aarch64:
        fmt = ExtraRegisters::NT_FPR;
        break;
    }
    bool ok = ret.recorded_extra_regs.set_to_raw_data(
        arch, fmt, extra_reg_data.begin(),
        extra_reg_data.size(), xsave_layout_from_trace(cpuid_records()));
    if (!ok) {
      FATAL() << "Invalid extended register data in trace";
    }
  } else {
    ret.recorded_extra_regs = ExtraRegisters(arch);
  }

  auto event = frame.getEvent();
  switch (event.which()) {
    case trace::Frame::Event::INSTRUCTION_TRAP:
      ret.ev = Event::instruction_trap();
      break;
    case trace::Frame::Event::PATCH_SYSCALL:
      ret.ev = Event::patch_syscall();
      break;
    case trace::Frame::Event::PATCH_TRAPPING_INSTRUCTION:
      ret.ev = Event::patch_syscall();
      ret.ev.PatchSyscall().patch_trapping_instruction = true;
      break;
    case trace::Frame::Event::PATCH_VSYSCALL:
      ret.ev = Event::patch_syscall();
      ret.ev.PatchSyscall().patch_vsyscall = true;
      break;
    case trace::Frame::Event::PATCH_AFTER_SYSCALL:
      ret.ev = Event::patch_syscall();
      ret.ev.PatchSyscall().patch_after_syscall = true;
      break;
    case trace::Frame::Event::SYSCALLBUF_ABORT_COMMIT:
      ret.ev = Event::syscallbuf_abort_commit();
      break;
    case trace::Frame::Event::SYSCALLBUF_RESET:
      ret.ev = Event::syscallbuf_reset();
      break;
    case trace::Frame::Event::SCHED:
      ret.ev = Event::sched();
      ret.ev.Sched().in_syscallbuf_syscall_hook = frame.getInSyscallbufSyscallHook();
      break;
    case trace::Frame::Event::GROW_MAP:
      ret.ev = Event::grow_map();
      break;
    case trace::Frame::Event::SIGNAL:
      ret.ev = from_trace_signal(EV_SIGNAL, event.getSignal());
      break;
    case trace::Frame::Event::SIGNAL_DELIVERY:
      ret.ev = from_trace_signal(EV_SIGNAL_DELIVERY, event.getSignalDelivery());
      break;
    case trace::Frame::Event::SIGNAL_HANDLER:
      ret.ev = from_trace_signal(EV_SIGNAL_HANDLER, event.getSignalHandler());
      break;
    case trace::Frame::Event::EXIT:
      ret.ev = Event::exit();
      break;
    case trace::Frame::Event::SYSCALLBUF_FLUSH: {
      ret.ev = Event(SyscallbufFlushEvent());
      auto mprotect_records = event.getSyscallbufFlush().getMprotectRecords();
      auto& records = ret.ev.SyscallbufFlush().mprotect_records;
      records.resize(mprotect_records.size() / sizeof(mprotect_record));
      if (records.data()) {
        memcpy(records.data(), mprotect_records.begin(),
               records.size() * sizeof(mprotect_record));
      }
      break;
    }
    case trace::Frame::Event::SYSCALL: {
      auto syscall = event.getSyscall();
      ret.ev = Event(SyscallEvent(syscall.getNumber(),
                                  from_trace_arch(syscall.getArch())));
      auto& syscall_ev = ret.ev.Syscall();
      syscall_ev.state = from_trace_syscall_state(syscall.getState());
      syscall_ev.failed_during_preparation =
          syscall.getFailedDuringPreparation();
      auto data = syscall.getExtra();
      switch (data.which()) {
        case trace::Frame::Event::Syscall::Extra::NONE:
          break;
        case trace::Frame::Event::Syscall::Extra::WRITE_OFFSET:
          syscall_ev.write_offset = data.getWriteOffset();
          if (syscall_ev.write_offset < 0) {
            FATAL() << "Write offset out of range";
          }
          break;
        case trace::Frame::Event::Syscall::Extra::EXEC_FDS_TO_CLOSE: {
          auto exec_fds = data.getExecFdsToClose();
          syscall_ev.exec_fds_to_close.resize(exec_fds.size());
          for (size_t i = 0; i < exec_fds.size(); ++i) {
            syscall_ev.exec_fds_to_close[i] = check_fd(exec_fds[i]);
          }
          break;
        }
        case trace::Frame::Event::Syscall::Extra::OPENED_FDS: {
          auto open = data.getOpenedFds();
          syscall_ev.opened.resize(open.size());
          for (size_t i = 0; i < open.size(); ++i) {
            auto& opened = syscall_ev.opened[i];
            const auto& o = open[i];
            opened.fd = check_fd(o.getFd());
            opened.path = data_to_str(o.getPath());
            opened.device = o.getDevice();
            opened.inode = o.getInode();
          }
          break;
        }
        case trace::Frame::Event::Syscall::Extra::SOCKET_ADDRS: {
          auto addrs = data.getSocketAddrs();
          syscall_ev.socket_addrs = make_shared<std::array<typename NativeArch::sockaddr_storage, 2>>();
          Data::Reader local = addrs.getLocalAddr();
          if (local.size() != sizeof(NativeArch::sockaddr_storage)) {
            FATAL() << "Invalid sockaddr length";
          }
          memcpy(&(*syscall_ev.socket_addrs.get())[0], local.begin(), sizeof(NativeArch::sockaddr_storage));
          Data::Reader remote = addrs.getRemoteAddr();
          if (remote.size() != sizeof(NativeArch::sockaddr_storage)) {
            FATAL() << "Invalid sockaddr length";
          }
          memcpy(&(*syscall_ev.socket_addrs.get())[1], remote.begin(), sizeof(NativeArch::sockaddr_storage));
          break;
        }
        case trace::Frame::Event::Syscall::Extra::MADVISE_RANGES: {
          auto mrs = data.getMadviseRanges();
          syscall_ev.madvise_ranges.resize(mrs.size());
          for (size_t i = 0; i < mrs.size(); ++i) {
            const auto& mr = mrs[i];
            syscall_ev.madvise_ranges[i] =
                MemoryRange(remote_ptr<void>(mr.getStart()), remote_ptr<void>(mr.getEnd()));
          }
          break;
        }
        default:
          FATAL() << "Unknown syscall type";
          break;
      }
      break;
    }
    default:
      FATAL() << "Event type not supported";
      break;
  }

  return ret;
}

void TraceWriter::write_task_event(const TraceTaskEvent& event) {
  MallocMessageBuilder task_msg;
  trace::TaskEvent::Builder task = task_msg.initRoot<trace::TaskEvent>();
  task.setFrameTime(global_time);
  task.setTid(event.tid());

  switch (event.type()) {
    case TraceTaskEvent::CLONE: {
      auto clone = task.initClone();
      clone.setParentTid(event.parent_tid());
      clone.setOwnNsTid(event.own_ns_tid());
      clone.setFlags(event.clone_flags());
      break;
    }
    case TraceTaskEvent::EXEC: {
      auto exec = task.initExec();
      exec.setFileName(str_to_data(event.file_name()));
      const auto& event_cmd_line = event.cmd_line();
      auto cmd_line = exec.initCmdLine(event_cmd_line.size());
      for (size_t i = 0; i < event_cmd_line.size(); ++i) {
        cmd_line.set(i, str_to_data(event_cmd_line[i]));
      }
      exec.setExeBase(event.exe_base().as_int());
      exec.setInterpBase(event.interp_base().as_int());
      exec.setInterpName(str_to_data(event.interp_name()));;
      auto pac_data = exec.initPacData();
      std::vector<uint8_t> pac_data_vec = event.pac_data();
      pac_data.setRaw(Data::Reader(pac_data_vec.data(), pac_data_vec.size()));
      break;
    }
    case TraceTaskEvent::EXIT:
      task.initExit().setExitStatus(event.exit_status().get());
      break;
    case TraceTaskEvent::DETACH:
      task.initDetach();
      break;
    case TraceTaskEvent::NONE:
      DEBUG_ASSERT(0 && "Writing NONE TraceTaskEvent");
      break;
  }

  try {
    auto& tasks = writer(TASKS);
    CompressedWriterOutputStream stream(tasks);
    writePackedMessage(stream, task_msg);
  } catch (...) {
    FATAL() << "Unable to write tasks";
  }
}

TraceTaskEvent TraceReader::read_task_event(FrameTime* time) {
  TraceTaskEvent r;
  auto& tasks = reader(TASKS);
  if (tasks.at_end()) {
    return r;
  }

  CompressedReaderInputStream stream(tasks);
  PackedMessageReader task_msg(stream);
  trace::TaskEvent::Reader task = task_msg.getRoot<trace::TaskEvent>();
  r.tid_ = i32_to_tid(task.getTid());
  if (time) {
    *time = task.getFrameTime();
  }
  switch (task.which()) {
    case trace::TaskEvent::Which::CLONE: {
      r.type_ = TraceTaskEvent::CLONE;
      auto clone = task.getClone();
      r.parent_tid_ = i32_to_tid(clone.getParentTid());
      // The record task could have died before we were able to compute this,
      // which we handle fine (since we'll see the exit event right away),
      // but we can't use i32_to_tid, which will assert if the tid is invalid.
      r.own_ns_tid_ = (pid_t)clone.getOwnNsTid();
      r.clone_flags_ = clone.getFlags();
      LOG(debug) << "Reading event for " << task.getFrameTime()
                 << ": parent=" << r.parent_tid_ << " tid=" << r.tid_;
      break;
    }
    case trace::TaskEvent::Which::EXEC: {
      r.type_ = TraceTaskEvent::EXEC;
      auto exec = task.getExec();
      r.file_name_ = data_to_str(exec.getFileName());
      auto cmd_line = exec.getCmdLine();
      r.cmd_line_.resize(cmd_line.size());
      for (size_t i = 0; i < cmd_line.size(); ++i) {
        r.cmd_line_[i] = data_to_str(cmd_line[i]);
      }
      r.exe_base_ = exec.getExeBase();
      r.interp_base_ = exec.getInterpBase();
      r.interp_name_ = data_to_str(exec.getInterpName());
      auto pac_data = exec.getPacData().getRaw();
      r.pac_data_ = std::vector<uint8_t>(pac_data.begin(), pac_data.end());
      break;
    }
    case trace::TaskEvent::Which::EXIT:
      r.type_ = TraceTaskEvent::EXIT;
      r.exit_status_ = WaitStatus(task.getExit().getExitStatus());
      break;
    case trace::TaskEvent::Which::DETACH:
      r.type_ = TraceTaskEvent::DETACH;
      break;
    default:
      DEBUG_ASSERT(0 && "Unknown TraceEvent type");
      break;
  }
  return r;
}

static string base_file_name(const string& file_name) {
  size_t last_slash = file_name.rfind('/');
  return (last_slash != file_name.npos) ? file_name.substr(last_slash + 1)
                                        : file_name;
}

bool TraceWriter::try_hardlink_file(const string& real_file_name,
                                    const string& access_file_name,
                                    std::string* new_name) {
  char count_str[20];
  sprintf(count_str, "%d", mmap_count);

  string path =
      string("mmap_hardlink_") + count_str + "_" + base_file_name(real_file_name);
  int ret = linkat(AT_FDCWD, access_file_name.c_str(), AT_FDCWD, (dir() + "/" + path).c_str(), AT_SYMLINK_FOLLOW);
  if (ret < 0) {
    return false;
  }
  *new_name = path;
  return true;
}

bool TraceWriter::try_clone_file(RecordTask* t,
    const string& real_file_name, const string& access_file_name,
    string* new_name) {
  if (!t->session().use_file_cloning()) {
    return false;
  }

  char count_str[20];
  sprintf(count_str, "%d", mmap_count);

  string path =
      string("mmap_clone_") + count_str + "_" + base_file_name(real_file_name);

  ScopedFd src(access_file_name.c_str(), O_RDONLY);
  if (!src.is_open()) {
    return false;
  }
  string dest_path = dir() + "/" + path;
  ScopedFd dest(dest_path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0700);
  if (!dest.is_open()) {
    return false;
  }

  int ret = ioctl(dest, BTRFS_IOC_CLONE, src.get());
  if (ret < 0) {
    // maybe not on the same filesystem, or filesystem doesn't support clone?
    unlink(dest_path.c_str());
    return false;
  }

  *new_name = path;
  return true;
}

bool TraceWriter::copy_file(const std::string& real_file_name,
                            const std::string& access_file_name,
                            std::string* new_name) {
  char count_str[20];
  sprintf(count_str, "%d", mmap_count);

  string path =
      string("mmap_copy_") + count_str + "_" + base_file_name(real_file_name);

  ScopedFd src(access_file_name.c_str(), O_RDONLY);
  if (!src.is_open()) {
    LOG(debug) << "Can't open " << access_file_name;
    return false;
  }
  string dest_path = dir() + "/" + path;
  ScopedFd dest(dest_path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0700);
  if (!dest.is_open()) {
    return false;
  }

  *new_name = path;

  return rr::copy_file(dest, src);
}

static bool starts_with(const string& s, const string& with) {
  return s.find(with) == 0;
}

TraceWriter::RecordInTrace TraceWriter::write_mapped_region(
    RecordTask* t, const KernelMapping& km,
    const struct stat& stat, const std::string &file_name,
    const vector<TraceRemoteFd>& extra_fds, MappingOrigin origin,
    bool skip_monitoring_mapped_fd) {
  MallocMessageBuilder map_msg;
  trace::MMap::Builder map = map_msg.initRoot<trace::MMap>();
  map.setFrameTime(global_time);
  map.setStart(km.start().as_int());
  map.setEnd(km.end().as_int());
  map.setFsname(str_to_data(km.fsname()));
  map.setDevice(km.device());
  map.setInode(km.inode());
  map.setProt(km.prot());
  map.setFlags(km.flags());
  map.setFileOffsetBytes(km.file_offset_bytes());
  map.setStatMode(stat.st_mode);
  map.setStatUid(stat.st_uid);
  map.setStatGid(stat.st_gid);
  map.setStatSize(stat.st_size);
  map.setStatMTime(stat.st_mtime);
  auto fds = map.initExtraFds(extra_fds.size());
  for (size_t i = 0; i < extra_fds.size(); ++i) {
    auto e = fds[i];
    auto& r = extra_fds[i];
    e.setTid(r.tid);
    e.setFd(r.fd);
  }
  map.setSkipMonitoringMappedFd(skip_monitoring_mapped_fd);
  auto src = map.getSource();
  string backing_file_name;

  auto copy_file_or_trace = [&](string file_name) {
    // Make executable files accessible to debuggers by copying the whole
    // thing into the trace directory. We don't get to compress the data and
    // the entire file is copied, not just the used region, which is why we
    // don't do this for all files.
    // Don't bother trying to copy [vdso].
    // Don't try to copy files that use shared mappings. We do not want to
    // create a shared mapping of a file stored in the trace. This means
    // debuggers can't find the file, but the Linux loader doesn't create
    // shared mappings so situations where a shared-mapped executable contains
    // usable debug info should be very rare at best...
    string backing_file_name;
    if ((km.prot() & PROT_EXEC) &&
        copy_file(km.fsname(), file_name, &backing_file_name) &&
        !(km.flags() & MAP_SHARED)) {
      src.initFile().setBackingFileName(str_to_data(backing_file_name));
    } else {
      src.setTrace();
    }
  };

  if (origin == REMAP_MAPPING || origin == PATCH_MAPPING ||
      origin == RR_BUFFER_MAPPING) {
    src.setZero();
  } else if (starts_with(km.fsname(), "/SYSV")) {
    src.setTrace();
  } else if (origin == SYSCALL_MAPPING &&
             (km.inode() == 0 || km.fsname_strip_deleted() == "/dev/zero")) {
    src.setZero();
  } else if (!starts_with(km.fsname(), "/")) {
    src.setTrace();
  } else {
    auto assumed_immutable =
        files_assumed_immutable.find(make_pair(stat.st_dev, stat.st_ino));

    if (assumed_immutable != files_assumed_immutable.end()) {
      src.initFile().setBackingFileName(str_to_data(assumed_immutable->second));
    } else if ((km.flags() & MAP_PRIVATE) &&
               try_clone_file(t, km.fsname(), file_name, &backing_file_name)) {
      src.initFile().setBackingFileName(str_to_data(backing_file_name));
    } else if (should_copy_mmap_region(km, file_name, stat)) {
      copy_file_or_trace(file_name);
    } else {
      // should_copy_mmap_region's heuristics determined it was OK to just map
      // the file here even if it's MAP_SHARED. So try cloning again to avoid
      // the possibility of the file changing between recording and replay.
      if (try_clone_file(t, km.fsname(), file_name, &backing_file_name)) {
        src.initFile().setBackingFileName(str_to_data(backing_file_name));
      } else {
        // Try hardlinking file into the trace directory. This will avoid
        // replay failures if the original file is deleted or replaced (but not
        // if it is overwritten in-place). If try_hardlink_file fails it
        // just returns the original file name.
        // A relative backing_file_name is relative to the trace directory.
        if (!try_hardlink_file(km.fsname(), file_name, &backing_file_name)) {
          // Don't ever use `file_name` for the `backing_file_name` because it
          // contains the pid of a recorded process and will not work!
          backing_file_name = km.fsname();
          // If the backing_file_name refers to a different file (e.g.
          // because we have a file in our mount namespace that matches the
          // fsname in the Task's mount namespace), then copy the file even
          // if the heuristics above thought we could get away with leaving it
          // in place. Otherwise, we're essentially guaranteed to have a broken
          // recording.
          struct stat backing_stat;
          int err = ::stat(backing_file_name.c_str(), &backing_stat);
          if (err != 0 || backing_stat.st_dev != km.device() ||
              backing_stat.st_ino != km.inode()) {
            copy_file_or_trace(file_name);
          } else {
            files_assumed_immutable.insert(
                make_pair(make_pair(stat.st_dev, stat.st_ino), backing_file_name));
            src.initFile().setBackingFileName(str_to_data(backing_file_name));
          }
        } else {
          files_assumed_immutable.insert(
            make_pair(make_pair(stat.st_dev, stat.st_ino), backing_file_name));
          src.initFile().setBackingFileName(str_to_data(backing_file_name));
        }
      }
    }
  }

  try {
    auto& mmaps = writer(MMAPS);
    CompressedWriterOutputStream stream(mmaps);
    writePackedMessage(stream, map_msg);
  } catch (...) {
    FATAL() << "Unable to write mmaps";
  }

  ++mmap_count;
  return src.isTrace() ? RECORD_IN_TRACE : DONT_RECORD_IN_TRACE;
}

void TraceWriter::write_mapped_region_to_alternative_stream(
    CompressedWriter& mmaps, const MappedData& data, const KernelMapping& km,
    const vector<TraceRemoteFd>& extra_fds, bool skip_monitoring_mapped_fd) {
  MallocMessageBuilder map_msg;
  trace::MMap::Builder map = map_msg.initRoot<trace::MMap>();

  map.setFrameTime(data.time);
  map.setStart(km.start().as_int());
  map.setEnd(km.end().as_int());
  map.setFsname(str_to_data(km.fsname()));
  map.setDevice(km.device());
  map.setInode(km.inode());
  map.setProt(km.prot());
  map.setFlags(km.flags());
  map.setFileOffsetBytes(km.file_offset_bytes());
  map.setStatSize(data.file_size_bytes);
  auto fds = map.initExtraFds(extra_fds.size());
  for (size_t i = 0; i < extra_fds.size(); ++i) {
    auto e = fds[i];
    auto& r = extra_fds[i];
    e.setTid(r.tid);
    e.setFd(r.fd);
  }
  map.setSkipMonitoringMappedFd(skip_monitoring_mapped_fd);
  auto src = map.getSource();
  switch (data.source) {
    case TraceReader::SOURCE_ZERO:
      src.setZero();
      break;
    case TraceReader::SOURCE_TRACE:
      src.setTrace();
      break;
    case TraceReader::SOURCE_FILE:
      src.initFile().setBackingFileName(str_to_data(data.file_name));
      break;
    default:
      FATAL() << "Unknown source type";
      break;
  }

  try {
    CompressedWriterOutputStream stream(mmaps);
    writePackedMessage(stream, map_msg);
  } catch (...) {
    FATAL() << "Unable to write mmaps";
  }
}

KernelMapping TraceReader::read_mapped_region(MappedData* data, bool* found,
                                              ValidateSourceFile validate,
                                              TimeConstraint time_constraint,
                                              vector<TraceRemoteFd>* extra_fds,
                                              bool* skip_monitoring_mapped_fd) {
  if (found) {
    *found = false;
  }

  auto& mmaps = reader(MMAPS);
  if (mmaps.at_end()) {
    return KernelMapping();
  }

  if (time_constraint == CURRENT_TIME_ONLY) {
    mmaps.save_state();
  }
  CompressedReaderInputStream stream(mmaps);
  PackedMessageReader map_msg(stream);
  trace::MMap::Reader map = map_msg.getRoot<trace::MMap>();
  if (time_constraint == CURRENT_TIME_ONLY) {
    if (map.getFrameTime() != global_time) {
      mmaps.restore_state();
      return KernelMapping();
    }
    mmaps.discard_state();
  }

  if (data) {
    data->time = map.getFrameTime();
    if (data->time <= 0) {
      FATAL() << "Invalid frameTime";
    }
    data->data_offset_bytes = 0;
    data->file_size_bytes = map.getStatSize();
    if (extra_fds) {
      const auto& fds = map.getExtraFds();
      for (size_t i = 0; i < fds.size(); ++i) {
        const auto& f = fds[i];
        extra_fds->push_back({ f.getTid(), f.getFd() });
      }
    }
    if (skip_monitoring_mapped_fd) {
      *skip_monitoring_mapped_fd = map.getSkipMonitoringMappedFd();
    }
    auto src = map.getSource();
    switch (src.which()) {
      case trace::MMap::Source::Which::ZERO:
        data->source = SOURCE_ZERO;
        break;
      case trace::MMap::Source::Which::TRACE:
        data->source = SOURCE_TRACE;
        break;
      case trace::MMap::Source::Which::FILE: {
        data->source = SOURCE_FILE;
        string backing_file_name =
            data_to_str(src.getFile().getBackingFileName());
        bool is_clone = starts_with(backing_file_name, "mmap_clone_");
        bool is_copy = starts_with(backing_file_name, "mmap_copy_");
        if (backing_file_name[0] != '/') {
          backing_file_name = dir() + "/" + backing_file_name;
        }
        uint32_t uid = map.getStatUid();
        uint32_t gid = map.getStatGid();
        uint32_t mode = map.getStatMode();
        int64_t mtime = map.getStatMTime();
        int64_t size = map.getStatSize();
        if (size < 0) {
          FATAL() << "Invalid statSize";
        }
        bool has_stat_buf = mode != 0 || uid != 0 || gid != 0 || mtime != 0;
        if (!is_clone && !is_copy && validate == VALIDATE && has_stat_buf) {
          struct stat backing_stat;
          if (stat(backing_file_name.c_str(), &backing_stat)) {
            FATAL() << "Failed to stat " << backing_file_name
                    << ": replay is impossible";
          }
          if (backing_stat.st_ino != map.getInode() ||
              backing_stat.st_mode != mode || backing_stat.st_uid != uid ||
              backing_stat.st_gid != gid || backing_stat.st_size != size ||
              backing_stat.st_mtime != mtime) {
            LOG(error) << "Metadata of " << data_to_str(map.getFsname())
                       << " changed: replay divergence likely, but continuing "
                          "anyway. inode: "
                       << backing_stat.st_ino << "/" << map.getInode()
                       << "; mode: " << backing_stat.st_mode << "/" << mode
                       << "; uid: " << backing_stat.st_uid << "/" << uid
                       << "; gid: " << backing_stat.st_gid << "/" << gid
                       << "; size: " << backing_stat.st_size << "/" << size
                       << "; mtime: " << backing_stat.st_mtime << "/" << mtime;
          }
        }
        data->file_name = backing_file_name;
        int64_t file_offset_bytes = map.getFileOffsetBytes();
        if (file_offset_bytes < 0) {
          FATAL() << "Invalid fileOffsetBytes";
        }
        data->data_offset_bytes = file_offset_bytes;
        break;
      }
      default:
        FATAL() << "Unknown mapping source";
        break;
    }
  }
  if (found) {
    *found = true;
  }
  return KernelMapping(map.getStart(), map.getEnd(),
                       data_to_str(map.getFsname()), map.getDevice(),
                       map.getInode(), map.getProt(), map.getFlags(),
                       map.getFileOffsetBytes());
}

void TraceWriter::write_raw_header(pid_t rec_tid, size_t total_len,
                                   remote_ptr<void> addr,
                                   const std::vector<WriteHole>& holes,
                                   MemWriteSizeValidation size_validation) {
  raw_recs.push_back({ addr, total_len, rec_tid, holes, size_validation });
}

void TraceWriter::write_raw_data(const void* d, size_t len) {
  auto& data = writer(RAW_DATA);
  data.write(d, len);
}

bool TraceReader::read_raw_data_for_frame(RawData& d) {
  if (raw_recs.empty()) {
    return false;
  }
  auto& rec = raw_recs[raw_recs.size() - 1];
  d.rec_tid = rec.rec_tid;
  d.addr = rec.addr;
  d.size_validation = rec.size_validation;

  d.data.resize(rec.size);
  auto hole_iter = rec.holes.begin();
  uintptr_t offset = 0;
  while (offset < d.data.size()) {
    uintptr_t end = rec.size;
    if (hole_iter != rec.holes.end()) {
      if (offset == hole_iter->offset) {
        memset(d.data.data() + offset, 0, hole_iter->size);
        offset += hole_iter->size;
        ++hole_iter;
        continue;
      }
      end = hole_iter->offset;
    }
    reader(RAW_DATA).read((char*)d.data.data() + offset, end - offset);
    offset = end;
  }

  raw_recs.pop_back();
  return true;
}

bool TraceReader::read_raw_data_for_frame_with_holes(RawDataWithHoles& d) {
  if (raw_recs.empty()) {
    return false;
  }
  auto& rec = raw_recs[raw_recs.size() - 1];
  d.rec_tid = rec.rec_tid;
  d.addr = rec.addr;
  d.holes = std::move(rec.holes);
  size_t data_size = rec.size;
  d.size_validation = rec.size_validation;
  for (auto& h : d.holes) {
    data_size -= h.size;
  }
  d.data.resize(data_size);
  reader(RAW_DATA).read((char*)d.data.data(), data_size);

  raw_recs.pop_back();
  return true;
}

bool TraceReader::read_raw_data_metadata_for_frame(RawDataMetadata& d) {
  if (raw_recs.empty()) {
    return false;
  }
  d = raw_recs[raw_recs.size() - 1];
  size_t data_size = d.size;
  for (auto& h : d.holes) {
    data_size -= h.size;
  }
  reader(RAW_DATA).skip(data_size);
  raw_recs.pop_back();
  return true;
}

static string create_unique_dir(const TraceOutputPath& path) {
    ensure_dir(path.output_trace_dir, "trace directory", S_IRWXU);

    // Find a unique trace directory name.
    int nonce = 0;
    int ret;
    string dir;
    do {
      stringstream ss;
      ss << path.output_trace_dir << "/" << basename(path.name.c_str()) << "-"
         << nonce++;
      dir = ss.str();
      ret = mkdir(dir.c_str(), S_IRWXU | S_IRWXG);
    } while (ret && EEXIST == errno);

    if (ret) {
      FATAL() << "Unable to create trace directory `" << dir << "'";
    }

    return dir;
}

static string make_trace_dir(const TraceOutputPath& path) {
  if (path.usr_provided_outdir) {
    // save trace dir in given output trace dir with option -o
    int ret = mkdir(path.output_trace_dir.c_str(), S_IRWXU | S_IRWXG);
    if(path.usr_provided_name) {
      return create_unique_dir(path);
    }
    if (ret == 0) {
      return path.output_trace_dir;
    }
    if (EEXIST == errno) {
      CLEAN_FATAL() << "Trace directory `" << path.output_trace_dir << "' already exists.";
    } else if (EACCES == errno) {
      CLEAN_FATAL() << "Permission denied to create trace directory `" << path.output_trace_dir << "'";
    } else {
      FATAL() << "Unable to create trace directory `" << path.output_trace_dir << "'";
    }
  } else {
    // save trace dir set in _RR_TRACE_DIR or in the default trace dir
    return create_unique_dir(path);
  }

  return ""; // not reached
}

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

TraceWriter::TraceWriter(const TraceOutputPath& trace_output,
                         TicksSemantics ticks_semantics_)
    : TraceStream(make_trace_dir(trace_output),
                  // Somewhat arbitrarily start the
                  // global time from 1.
                  1),
      ticks_semantics_(ticks_semantics_),
      mmap_count(0),
      has_cpuid_faulting_(false),
      xsave_fip_fdp_quirk_(false),
      fdp_exception_only_quirk_(false),
      clear_fip_fdp_(false),
      supports_file_data_cloning_(false),
      chaos_mode(false)
       {
  this->ticks_semantics_ = ticks_semantics_;

  for (Substream s = SUBSTREAM_FIRST; s < SUBSTREAM_COUNT; ++s) {
    writers[s] = unique_ptr<CompressedWriter>(new CompressedWriter(
        path(s), substream(s).block_size, substream(s).threads));
  }

  string ver_path = incomplete_version_path();
  version_fd = ScopedFd(ver_path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  if (!version_fd.is_open()) {
    FATAL() << "Unable to create " << ver_path;
  }
  // Take an exclusive lock and hold it until we rename the file at
  // the end of recording and then close our file descriptor.
  if (flock(version_fd, LOCK_EX | LOCK_NB) != 0) {
    FATAL() << "Unable to lock " << ver_path;
  }
  static const char buf[] = STR(TRACE_VERSION) "\n";
  size_t buf_len = sizeof(buf) - 1;
  if (write(version_fd, buf, buf_len) != (ssize_t)buf_len) {
    FATAL() << "Unable to write " << ver_path;
  }

  // Test if file data cloning is supported
  string version_clone_path = trace_dir + "/tmp_clone";
  ScopedFd version_clone_fd(version_clone_path.c_str(), O_WRONLY | O_CREAT,
                            0600);
  if (!version_clone_fd.is_open()) {
    FATAL() << "Unable to create " << version_clone_path;
  }
  btrfs_ioctl_clone_range_args clone_args;
  clone_args.src_fd = version_fd;
  clone_args.src_offset = 0;
  clone_args.src_length = buf_len;
  clone_args.dest_offset = 0;
  if (ioctl(version_clone_fd, BTRFS_IOC_CLONE_RANGE, &clone_args) == 0) {
    supports_file_data_cloning_ = true;
  }
  unlink(version_clone_path.c_str());

  if (!probably_not_interactive(STDOUT_FILENO)) {
    printf("rr: Saving execution to trace directory `%s'.\n",
           trace_dir.c_str());
  }
}

void TraceWriter::setup_cpuid_records(bool has_cpuid_faulting,
                                      const DisableCPUIDFeatures& disable_cpuid_features) {
  has_cpuid_faulting_ = has_cpuid_faulting;
  // We are now bound to the selected CPU (if any), so collect CPUID records
  // (which depend on the bound CPU number).
  cpuid_records = all_cpuid_records();
  // Modify the recorded cpuid data only if cpuid faulting is available. If it
  // is not available, the tracee will see unmodified data and should also see
  // that in handle_unrecorded_cpuid_fault (which is sourced from this data).
  if (has_cpuid_faulting) {
    for (auto& r : cpuid_records) {
      disable_cpuid_features.amend_cpuid_data(r.eax_in, r.ecx_in, &r.out);
    }
  }
}

void TraceWriter::close(CloseStatus status, const TraceUuid* uuid) {
  for (auto& w : writers) {
    w->close();
  }

  MallocMessageBuilder header_msg;
  trace::Header::Builder header = header_msg.initRoot<trace::Header>();
  header.setBindToCpu(this->bind_to_cpu);
  header.setTicksSemantics(
    to_trace_ticks_semantics(PerfCounters::default_ticks_semantics()));
  header.setSyscallbufProtocolVersion(SYSCALLBUF_PROTOCOL_VERSION);
  header.setRequiredForwardCompatibilityVersion(FORWARD_COMPATIBILITY_VERSION);
  header.setPreloadThreadLocalsRecorded(true);
  header.setRrcallBase(syscall_number_for_rrcall_init_preload(x86_64));
  header.setSyscallbufFdsDisabledSize(SYSCALLBUF_FDS_DISABLED_SIZE);
  header.setSyscallbufHdrSize(sizeof(syscallbuf_hdr));

  header.setNativeArch(to_trace_arch(NativeArch::arch()));
  if (NativeArch::is_x86ish())
  {
    auto x86data = header.initX86();
    x86data.setHasCpuidFaulting(has_cpuid_faulting_);
    x86data.setCpuidRecords(
        Data::Reader(reinterpret_cast<const uint8_t*>(cpuid_records.data()),
                    cpuid_records.size() * sizeof(CPUIDRecord)));
    x86data.setXcr0(xcr0());
    x86data.setXsaveFipFdpQuirk(to_tristate(xsave_fip_fdp_quirk_));
    x86data.setFdpExceptionOnlyQuirk(to_tristate(fdp_exception_only_quirk_));
    x86data.setClearFipFdp(clear_fip_fdp_);
  }

  {
    auto quirks = header.initQuirks();
    quirks.setExplicitProcMem(false);
    quirks.setSpecialLibrrpage(false);
    quirks.setPkeyAllocRecordedExtraRegs(true);
    quirks.setBufferedSyscallForcedTick(true);
    quirks.setUsesGlobalsInReplay(false);
  }
  // Add a random UUID to the trace metadata. This lets tools identify a trace
  // easily.
  if (!uuid) {
    uint8_t uuid[sizeof(TraceUuid::bytes)];
    good_random(uuid, sizeof(uuid));
    header.setUuid(Data::Reader(uuid, sizeof(uuid)));
  } else {
    header.setUuid(Data::Reader(uuid->bytes, sizeof(TraceUuid::bytes)));
  }
  header.setOk(status == CLOSE_OK);
  header.setChaosMode(chaos_mode ? trace::ChaosMode::KNOWN_TRUE : trace::ChaosMode::KNOWN_FALSE);
  MemoryRange exclusion_range = AddressSpace::get_global_exclusion_range(nullptr);
  header.setExclusionRangeStart(exclusion_range.start().as_int());
  header.setExclusionRangeEnd(exclusion_range.end().as_int());
  header.setRuntimePageSize(page_size());
  header.setPreloadLibraryPageSize(PRELOAD_LIBRARY_PAGE_SIZE);

  {
    struct utsname uname_buf;
    int ret = uname(&uname_buf);
    if (ret) {
      FATAL() << "uname failed";
    }
    auto uname_msg = header.initUname();
    uname_msg.setSysname(str_to_data(uname_buf.sysname));
    uname_msg.setNodename(str_to_data(uname_buf.nodename));
    uname_msg.setRelease(str_to_data(uname_buf.release));
    uname_msg.setVersion(str_to_data(uname_buf.version));
    uname_msg.setMachine(str_to_data(uname_buf.machine));
    uname_msg.setDomainname(str_to_data(uname_buf.domainname));
  }

  try {
    writePackedMessageToFd(version_fd, header_msg);
  } catch (...) {
    FATAL() << "Unable to write " << incomplete_version_path();
  }

  string incomplete_path = incomplete_version_path();
  string path = version_path();
  if (rename(incomplete_path.c_str(), path.c_str()) < 0) {
    FATAL() << "Unable to create version file " << path;
  }
  version_fd.close();
}

void TraceWriter::make_latest_trace() {
  string link_name = latest_trace_symlink();
  // Try to update the symlink to |this|.  We only try attempt
  // to set the symlink once.  If the link is re-created after
  // we |unlink()| it, then another rr process is racing with us
  // and it "won".  The link is then valid and points at some
  // very-recent trace, so that's good enough.
  unlink(link_name.c_str());
  // Link only the trace name, not the full path, so moving a directory full
  // of traces around doesn't break the latest-trace link.
  const char* trace_name = trace_dir.c_str();
  const char* last = strrchr(trace_name, '/');
  if (last) {
    trace_name = last + 1;
  }
  int ret = symlink(trace_name, link_name.c_str());
  if (ret < 0 && errno != EEXIST) {
    FATAL() << "Failed to update symlink `" << link_name << "' to `"
            << trace_dir << "'.";
  }
}

TraceFrame TraceReader::peek_frame() {
  auto& events = reader(EVENTS);
  events.save_state();
  auto saved_time = global_time;
  auto saved_raw_recs = raw_recs;
  TraceFrame frame;
  if (!at_end()) {
    frame = read_frame();
  }
  events.restore_state();
  global_time = saved_time;
  raw_recs = saved_raw_recs;
  return frame;
}

void TraceReader::rewind() {
  for (Substream s = SUBSTREAM_FIRST; s < SUBSTREAM_COUNT; ++s) {
    reader(s).rewind();
  }
  global_time = 0;
  DEBUG_ASSERT(good());
}

TraceReader::TraceReader(const string& dir)
    : TraceStream(resolve_trace_name(dir), 1) {
  for (Substream s = SUBSTREAM_FIRST; s < SUBSTREAM_COUNT; ++s) {
    readers[s] = unique_ptr<CompressedReader>(new CompressedReader(path(s)));
  }

  string path = version_path();
  ScopedFd version_fd(path.c_str(), O_RDONLY);
  if (!version_fd.is_open()) {
    if (errno == ENOENT) {
      string incomplete_path = incomplete_version_path();
      if (access(incomplete_path.c_str(), F_OK) == 0) {
        fprintf(
            stderr,
            "\n"
            "rr: Trace file `%s' found.\n"
            "rr recording terminated abnormally and the trace is incomplete.\n"
            "\n",
            incomplete_path.c_str());
      } else {
        fprintf(stderr,
                "\n"
                "rr: Trace file `%s' not found. There is no trace there.\n"
                "\n",
                path.c_str());
      }
    } else {
      fprintf(stderr, "\n"
                      "rr: Trace file `%s' not readable.\n"
                      "\n",
              path.c_str());
    }
    exit(EX_DATAERR);
  }
  string version_str;
  while (true) {
    char ch;
    ssize_t ret = read(version_fd, &ch, 1);
    if (ret <= 0) {
      FATAL() << "Can't read version file " << path;
    }
    if (ch == '\n') {
      break;
    }
    version_str += ch;
  }
  char* end_ptr;
  long int version = strtol(version_str.c_str(), &end_ptr, 10);
  if (*end_ptr != 0) {
    FATAL() << "Invalid version: " << version_str;
  }
  if (TRACE_VERSION != version) {
    fprintf(stderr, "\n"
                    "rr: error: Recorded trace `%s' has an incompatible "
                    "version %ld; expected\n"
                    "           %d.  Did you record `%s' with an older version "
                    "of rr?  If so,\n"
                    "           you'll need to replay `%s' with that older "
                    "version.  Otherwise,\n"
                    "           your trace is likely corrupted.\n"
                    "\n",
            path.c_str(), version, TRACE_VERSION, path.c_str(), path.c_str());
    exit(EX_DATAERR);
  }

  PackedFdMessageReader header_msg(version_fd);

  trace::Header::Reader header = header_msg.getRoot<trace::Header>();
  uint16_t syscallbuf_protocol_version = header.getSyscallbufProtocolVersion();
  if (syscallbuf_protocol_version > SYSCALLBUF_PROTOCOL_VERSION) {
    fprintf(stderr, "\n"
                    "rr: error: Recorded trace `%s' has an incompatible "
                    "syscallbuf protocol version %d; expected\n"
                    "           %d.  Did you record `%s' with an older version "
                    "of rr?  If so,\n"
                    "           you'll need to replay `%s' with that older "
                    "version.  Otherwise,\n"
                    "           your trace is likely corrupted.\n"
                    "\n",
            path.c_str(), syscallbuf_protocol_version, SYSCALLBUF_PROTOCOL_VERSION, path.c_str(), path.c_str());
    exit(EX_DATAERR);
  }
  bind_to_cpu = header.getBindToCpu();
  preload_thread_locals_recorded_ = header.getPreloadThreadLocalsRecorded();
  ticks_semantics_ = from_trace_ticks_semantics(header.getTicksSemantics());
  rrcall_base_ = header.getRrcallBase();
  syscallbuf_fds_disabled_size_ = header.getSyscallbufFdsDisabledSize();
  syscallbuf_hdr_size_ = header.getSyscallbufHdrSize();
  required_forward_compatibility_version_ = header.getRequiredForwardCompatibilityVersion();
  quirks_ = 0;
  {
    auto quirks = header.getQuirks();
    if (quirks.getExplicitProcMem()) {
      quirks_ |= ExplicitProcMem;
    }
    if (quirks.getSpecialLibrrpage()) {
      quirks_ |= SpecialLibRRpage;
    }
    if (quirks.getPkeyAllocRecordedExtraRegs()) {
      quirks_ |= PkeyAllocRecordedExtraRegs;
    }
    if (quirks.getBufferedSyscallForcedTick()) {
      quirks_ |= BufferedSyscallForcedTick;
    }
    if (quirks.getUsesGlobalsInReplay()) {
      quirks_ |= UsesGlobalsInReplay;
    }
  }
  Data::Reader uuid = header.getUuid();
  uuid_ = unique_ptr<TraceUuid>(new TraceUuid());
  if (uuid.size() != sizeof(uuid_->bytes)) {
    FATAL() << "Invalid UUID length";
  }
  memcpy(uuid_->bytes, uuid.begin(), sizeof(uuid_->bytes));

  arch_ = from_trace_arch(header.getNativeArch());
  if (is_x86ish(arch_)) {
    auto x86data = header.getX86();
    trace_uses_cpuid_faulting = x86data.getHasCpuidFaulting();
    Data::Reader cpuid_records_bytes = x86data.getCpuidRecords();
    size_t len = cpuid_records_bytes.size() / sizeof(CPUIDRecord);
    if (cpuid_records_bytes.size() != len * sizeof(CPUIDRecord)) {
      FATAL() << "Invalid CPUID records length";
    }
    cpuid_records_.resize(len);
    memcpy(cpuid_records_.data(), cpuid_records_bytes.begin(),
          len * sizeof(CPUIDRecord));
    xcr0_ = x86data.getXcr0();
    clear_fip_fdp_ = x86data.getClearFipFdp();
  }

  switch (header.getChaosMode()) {
    case trace::ChaosMode::UNKNOWN:
      chaos_mode_known_ = false;
      chaos_mode_ = false;
      break;
    case trace::ChaosMode::KNOWN_TRUE:
      chaos_mode_known_ = true;
      chaos_mode_ = true;
      break;
    case trace::ChaosMode::KNOWN_FALSE:
      chaos_mode_known_ = true;
      chaos_mode_ = false;
      break;
  }
  exclusion_range_ = MemoryRange(remote_ptr<void>(header.getExclusionRangeStart()),
                                 remote_ptr<void>(header.getExclusionRangeEnd()));

  const auto& uname = header.getUname();
  uname_.sysname = data_to_str(uname.getSysname());
  uname_.nodename = data_to_str(uname.getNodename());
  uname_.release = data_to_str(uname.getRelease());
  uname_.version = data_to_str(uname.getVersion());
  uname_.machine = data_to_str(uname.getMachine());
  uname_.domainname = data_to_str(uname.getDomainname());

  // Set the global time at 0, so that when we tick it for the first
  // event, it matches the initial global time at recording, 1.
  global_time = 0;
}

/**
 * Create a copy of this stream that has exactly the same
 * state as 'other', but for which mutations of this
 * clone won't affect the state of 'other' (and vice versa).
 */
TraceReader::TraceReader(const TraceReader& other)
    : TraceStream(other.dir(), other.time()) {
  for (Substream s = SUBSTREAM_FIRST; s < SUBSTREAM_COUNT; ++s) {
    readers[s] =
        unique_ptr<CompressedReader>(new CompressedReader(other.reader(s)));
  }

  bind_to_cpu = other.bind_to_cpu;
  trace_uses_cpuid_faulting = other.trace_uses_cpuid_faulting;
  cpuid_records_ = other.cpuid_records_;
  raw_recs = other.raw_recs;
  xcr0_ = other.xcr0_;
  preload_thread_locals_recorded_ = other.preload_thread_locals_recorded_;
  rrcall_base_ = other.rrcall_base_;
  arch_ = other.arch_;
  chaos_mode_ = other.chaos_mode_;
  chaos_mode_known_ = other.chaos_mode_known_;
  exclusion_range_ = other.exclusion_range_;
  uname_ = other.uname_;
  quirks_ = other.quirks_;
  clear_fip_fdp_ = other.clear_fip_fdp_;
  required_forward_compatibility_version_ = other.required_forward_compatibility_version_;
}

TraceReader::~TraceReader() {}

uint64_t TraceReader::uncompressed_bytes() const {
  uint64_t total = 0;
  for (Substream s = SUBSTREAM_FIRST; s < SUBSTREAM_COUNT; ++s) {
    total += reader(s).uncompressed_bytes();
  }
  return total;
}

uint64_t TraceReader::compressed_bytes() const {
  uint64_t total = 0;
  for (Substream s = SUBSTREAM_FIRST; s < SUBSTREAM_COUNT; ++s) {
    total += reader(s).compressed_bytes();
  }
  return total;
}

uint64_t TraceReader::xcr0() const {
  if (xcr0_) {
    return xcr0_;
  }
  // All valid XCR0 values have bit 0 (x87) == 1. So this is the default
  // value for traces that didn't store XCR0. Assume that the OS enabled
  // all CPU-supported XCR0 bits.
  const CPUIDRecord* record =
    find_cpuid_record(cpuid_records_, CPUID_GETXSAVE, 0);
  if (!record) {
    // No XSAVE support at all on the recording CPU??? Assume just
    // x87/SSE enabled.
    return 3;
  }
  return (uint64_t(record->out.edx) << 32) | record->out.eax;
}

} // namespace rr
