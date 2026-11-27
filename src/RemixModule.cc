/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "RemixModule.h"

#include <elf.h>
#include <limits.h>
#include <sys/uio.h>

#include <algorithm>
#include <sstream>

#include "AutoRemoteSyscalls.h"
#include "ElfReader.h"
#include "Flags.h"
#include "ReplaySession.h"
#include "ReplayTask.h"
#include "ScopedFd.h"
#include "kernel_metadata.h"
#include "log.h"

#include "remix/remix.h"

using namespace std;

namespace rr {

/**
 * Allocate 1MB of stack for use by the remix library, minus one guard page.
 */
static const ssize_t stack_size = 1024 * 1024;

/**
 * Allocate 128MB of memory for our "before-write" buffer.
 */
static const ssize_t saved_before_write_size = 128 * 1024 * 1024;

void RemixModule::unload(ReplayTask* t) {
  flush_modified_ranges(t);
  remote_code_ptr unload_fn = find_code_symbol("remix_will_unload");
  if (unload_fn) {
    call(t, unload_fn);
  }

  AutoRemoteSyscalls remote(t);
  remote.infallible_syscall(syscall_number_for_munmap(remote.arch()), mem_base,
                            mem_end - mem_base);
}

void RemixModule::map_segments(ReplayTask* t, const string& file_name,
                               ElfFileReader& reader) {
  AutoRemoteSyscalls remote(t);

  ASSERT(t, stack_size == ceil_page_size(stack_size));
  // Leave a guard page to catch stack overflows
  ASSERT(t, mem_end - mem_base > stack_size) << "OOM allocating stack";
  stack_start = mem_end - stack_size;
  remote.infallible_mmap_syscall_if_alive(
      stack_start + page_size(), stack_size - page_size(),
      PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
  // Register the mapping so that Task::safe_pwrite64 will have the correct
  // view of memory.
  t->vm()->map(t, stack_start + page_size(), stack_size - page_size(),
               PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
               0, string(), KernelMapping::NO_DEVICE, KernelMapping::NO_INODE);

  ASSERT(t, stack_start - mem_base > saved_before_write_size)
      << "OOM allocating saved_before_write";
  saved_before_write_start = stack_start - saved_before_write_size;
  remote.infallible_mmap_syscall_if_alive(
      saved_before_write_start, saved_before_write_size - page_size(),
      PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);

  AutoRestoreMem mem(remote, file_name.c_str());
  int fd = remote.infallible_syscall(syscall_number_for_open(remote.arch()),
                                     mem.get(), O_RDONLY);
  module_end = mem_base;
  for (auto& seg : reader.read_segments()) {
    if (seg.type != PT_LOAD) {
      continue;
    }
    remote_ptr<void> addr = mem_base + seg.mem_offset;
    int prot = 0;
    if (seg.flags & PF_R) {
      prot |= PROT_READ;
    }
    if (seg.flags & PF_W) {
      prot |= PROT_WRITE;
    }
    if (seg.flags & PF_X) {
      prot |= PROT_EXEC;
    }
    uintptr_t addr_page_offset = addr.as_int() & (page_size() - 1);
    ASSERT(t, addr_page_offset == (seg.file_offset & (page_size() - 1)))
        << "Malformed ELF image: LOAD segment not page aligned";
    remote.infallible_mmap_syscall_if_alive(
        addr - addr_page_offset, seg.file_size + addr_page_offset, prot,
        MAP_PRIVATE | MAP_FIXED, fd,
        seg.file_offset - addr_page_offset);
    // It's important that AddressSpace has the write prot bits here.
    t->vm()->map(t, addr - addr_page_offset, seg.file_size + addr_page_offset,
                 prot, MAP_PRIVATE | MAP_FIXED, 0, string(),
                 KernelMapping::NO_DEVICE, KernelMapping::NO_INODE);
    remote_ptr<void> file_end = addr + seg.file_size;
    remote_ptr<void> segment_end = addr + seg.mem_size;
    ASSERT(t, segment_end < free_end()) << "OOM mapping segment";
    if (file_end < segment_end) {
      remote_ptr<void> file_pages_end = ceil_page_size(file_end);
      if (file_pages_end < segment_end) {
        remote.infallible_mmap_syscall_if_alive(
            file_pages_end, segment_end - file_pages_end, prot,
            MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
        // It's important that AddressSpace has the write prot bits here.
        t->vm()->map(t, file_pages_end, segment_end - file_pages_end,
                     prot, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, 0, string(),
                     KernelMapping::NO_DEVICE, KernelMapping::NO_INODE);
      }
      remote_ptr<void> zero_end = min(file_pages_end, segment_end);
      if (file_end < zero_end) {
        vector<uint8_t> zeroes;
        zeroes.resize(zero_end - file_end);
        memset(zeroes.data(), 0, zeroes.size());
        t->write_bytes_helper(file_end, zeroes.size(), zeroes.data());
      }
    }
    module_end = max(module_end, ceil_page_size(segment_end));
  }
  remote.infallible_syscall(syscall_number_for_close(remote.arch()), fd);
}

void RemixModule::apply_relocations(ReplayTask* t, ElfFileReader& reader) {
  ASSERT(t, t->arch() == x86_64) << "Only x86-64 supported at this time";
  vector<struct iovec> remote;
  vector<uint64_t> buffer;
  uint64_t remote_last = UINT64_MAX;
  auto callback = [&](uint64_t offset, uint64_t info, uint64_t addend) {
    ASSERT(t, info == R_X86_64_RELATIVE)
        << "Only R_X86_64_RELATIVE relocations supported at this time";
    buffer.push_back(mem_base.as_int() + addend);
    uint64_t mem_offset = mem_base.as_int() + offset;
    if (remote_last == mem_offset) {
      remote[remote.size() - 1].iov_len += 8;
    } else {
      remote.push_back({ (void*)mem_offset, 8 });
    }
    remote_last = mem_offset + 8;
  };
  reader.iterate_relocations(callback);

  size_t index = 0;
  size_t buf_offset = 0;
  while (index < remote.size()) {
    size_t iov_count = min<size_t>(IOV_MAX, remote.size() - index);
    size_t bytes = 0;
    for (size_t i = index; i < index + iov_count; ++i) {
      bytes += remote[i].iov_len;
    }
    struct iovec local = { reinterpret_cast<char*>(buffer.data()) + buf_offset,
                           bytes };
    ssize_t ret = process_vm_writev(t->tid, &local, 1, remote.data() + index,
                                    iov_count, 0);
    ASSERT(t, ret == ssize_t(bytes));
    index += iov_count;
    buf_offset += bytes;
  }
}

void RemixModule::load_symbols(ElfFileReader& reader) {
  SymbolTable syms = reader.read_symbols(".dynsym", ".dynstr");
  for (size_t i = 0; i < syms.size(); ++i) {
    const char* name = syms.name(i);
    if (name && !strncmp(name, "remix_", 6)) {
      symbols.insert(make_pair(string(name), mem_base + syms.addr(i)));
    }
  }
}

void RemixModule::setup_rr_page_syscalls(ReplayTask* t) {
  auto rr_page_syscalls =
      find_symbol("remix_rr_page_syscalls").cast<RRPageSyscall>();
  ASSERT(t, !rr_page_syscalls.is_null());

  vector<RRPageSyscall> addrs;
  for (auto& c : t->vm()->rr_page_syscalls()) {
    RRPageSyscall syscall = { AddressSpace::rr_page_syscall_entry_point(
                                  c.traced, c.privileged, c.enabled, t->arch())
                                  .register_value(),
                              (SyscallTraced)c.traced,
                              (SyscallPrivileged)c.privileged,
                              (SyscallEnabled)c.enabled };
    addrs.push_back(syscall);
  }
  ASSERT(t, addrs.size() <= REMIX_MAX_RR_PAGE_SYSCALLS);

  t->write_mem(rr_page_syscalls, addrs.data(), addrs.size());
}

static RemixAddressSpaceUid to_remix_uid(const AddressSpaceUid& uid) {
  return { uid.tid(), uid.serial(), uid.exec_count() };
}

static uintptr_t watch_addr = 0;
static FrameTime singlestep_at = 0;
static bool show_only_ticks = false;
static bool show_module_steps = false;

static void set_tracing_from_environment() {
  const char* singlestep = getenv("RR_REMIX_SINGLESTEP_AT");
  if (singlestep) {
    singlestep_at = atoi(singlestep);
  }
}

static bool cpu_is_amd() {
  static bool result = is_cpu_amd(all_cpuid_records());
  return result;
}

static bool cpu_has_lzcnt() {
  static bool result = is_cpu_abm_enabled(all_cpuid_records());
  return result;
}

static bool cpu_has_tzcnt() {
  static bool result = is_cpu_bmi1_enabled(all_cpuid_records());
  return result;
}

RemixModule::RemixModule(ReplayTask* t, const MemoryRange& mem,
                         const string& path, shared_ptr<RemixToolHost> host,
                         intptr_t cookie, RemixTestOptions test_options)
    : host(move(host)),
      mem_base(mem.start()),
      mem_end(mem.end()),
      last_saved_before_write_data(0),
      last_saved_before_write_data_len(0),
      last_stop_reason(STOPPED_NULL),
      need_to_call_did_fork_child(false),
      in_call(false) {
  ASSERT(t,
         floor_page_size(mem.start()) == mem.start() &&
             floor_page_size(mem.end()) == mem.end());
  if (t->arch() != x86_64) {
    STRUCTURED_FATAL("RemixArchitectureNotSupported").task(t) << "Only x86-64 supported currently";
  }
  ASSERT(t, NativeArch::arch() == t->arch());
  tool_path_ = path;
  file_name = path + string(".so");
  ScopedFd fd(file_name.c_str(), O_RDONLY);
  ASSERT(t, fd.is_open()) << "Can't open " << file_name;
  ElfFileReader reader(fd, t->arch());
  ASSERT(t, reader.ok()) << "Can't map remix module " << file_name;

  /* On some machines (e.g. our c5d.9xls) PROT_EXEC does not imply PROT_READ
   * while on others (e.g. khuey's desktop) it does. remix needs to be able
   * to read code that's executed. We iterate through the mappings here and
   * if we find one that's PROT_EXEC but not PROT_READ, we add PROT_READ.
   *
   * In theory if we unload remix we should undo this change. We'll cross that
   * bridge if we ever come to it.
   */
  {
    vector<KernelMapping> mappings_to_fix;
    for (const auto& m : t->vm()->maps()) {
      auto prot = m.map.prot();
      if (!(prot & PROT_EXEC)) {
        continue;
      }
      if (prot & PROT_READ) {
        continue;
      }
      if (m.map.is_vsyscall()) {
        continue;
      }
      mappings_to_fix.push_back(m.map);
    }

    if (!mappings_to_fix.empty()) {
      AutoRemoteSyscalls remote(t);
      const int mprotect_syscallno = syscall_number_for_mprotect(t->arch());
      for (auto& m : mappings_to_fix) {
        LOG(debug) << "Fixing executable but not readable mapping at " << m.start();
        remote.infallible_syscall_if_alive(mprotect_syscallno, m.start(), m.size(), m.prot() | PROT_READ);
        t->vm()->protect(t, m.start(), m.size(), m.prot() | PROT_READ,
                         AddressSpace::MPROTECT_SYSCALL);
      }
    }
  }

  map_segments(t, file_name, reader);
  LOG(debug) << "Mapped " << file_name << " at " << mem_base << "; use `"
      << RemixModule::gdb_helpers() << "` to debug";
  apply_relocations(t, reader);
  load_symbols(reader);

  set_log_modules_from_environment(t);

  set_tracing_from_environment();

  execute_fn = find_code_symbol("remix_execute");
  wx_sighandler = find_code_symbol("remix_wx_sighandler");
  remix_registers = find_symbol("remix_registers").cast<uint8_t>();
  remix_rcb = find_symbol("remix_rcb").cast<uint64_t>();
  remix_target_registers = find_symbol("remix_target_registers").cast<uint8_t>();
  remix_target_rcb = find_symbol("remix_target_rcb").cast<uint64_t>();
  remix_sighandler_state = find_symbol("remix_sighandler_state").cast<RemixSighandlerState>();
  remix_crash_handler = find_symbol("remix_crash_handler").cast<remote_code_ptr>();
  remix_enable_stack_extension = find_symbol("remix_enable_stack_extension").cast<bool>();

  remote_ptr<uintptr_t> remix_range_start = find_symbol("remix_range_start").cast<uintptr_t>();
  remote_ptr<uintptr_t> remix_range_end = find_symbol("remix_range_end").cast<uintptr_t>();
  t->write_mem(remix_range_start, mem_base.as_int());
  t->write_mem(remix_range_end, mem_end.as_int());

  remote_code_ptr init_fn = find_code_symbol("remix_init");
  if (init_fn) {
    auto remix_uid = to_remix_uid(t->vm()->uid());
    uint32_t flags = 0;
    // If the trace uses CPUID faulting, generate those faults.
    if (t->session().trace_reader().uses_cpuid_faulting()) {
      flags |= REMIX_INIT_CPUID_FAULTING;
    }
    bool is_amd = test_options.force_emulate_amd || cpu_is_amd();
    if (is_amd != is_cpu_amd(t->session().trace_reader().cpuid_records())) {
      flags |= REMIX_INIT_CORRECT_RCP_RSQRT;
    }
    bool has_lzcnt = !test_options.force_emulate_no_lzcnt_tzcnt && cpu_has_lzcnt();
    if (has_lzcnt != is_cpu_abm_enabled(t->session().trace_reader().cpuid_records())) {
      flags |= REMIX_INIT_CORRECT_LZCNT;
    }
    bool has_tzcnt = !test_options.force_emulate_no_lzcnt_tzcnt && cpu_has_tzcnt();
    if (has_tzcnt != is_cpu_bmi1_enabled(t->session().trace_reader().cpuid_records())) {
      flags |= REMIX_INIT_CORRECT_TZCNT;
    }
    if (t->session().remix_needs_xsave_emulation() || test_options.force_emulate_xsave_region_layout_difference) {
      flags |= REMIX_INIT_CORRECT_XSAVE_REGION_LAYOUT;
    }

    init_cookie = call(t, init_fn, &remix_uid, free_start(), free_end(), cookie,
                       flags,
                       t->session().trace_reader().xcr0());

    for (auto& record: t->session().trace_reader().cpuid_records()) {
      if (record.eax_in == 0xd) {
        notify_remix_apply_quirk(t, RemixQuirk::XSAVE_COMPONENT_DATA, record.ecx_in,
                                 record.out.eax, record.out.ebx, record.out.ecx);
      }
    }
  } else {
    init_cookie = 0;
  }

  module_flags =
      t->read_mem(find_symbol("remix_module_flags").cast<uint64_t>());

  if (this->host) {
    this->host->notify_remix_module_attach(t, this);
  }

  for (const auto& m : t->vm()->maps()) {
    modified_ranges.push_back({ m.map.start().as_int(), m.map.end().as_int(), 0,
                                t->trace_reader().time(), m.map.prot(),
                                MEM_MAP });
    if (this->host) {
      this->host->notify_mapped(t, this, m.map, m.map.prot());
    }
  }

  setup_rr_page_syscalls(t);
}

RemixModule::RemixModule(const RemixModule& other)
    : host(other.host),
      mem_base(other.mem_base),
      module_end(other.module_end),
      saved_before_write_start(other.saved_before_write_start),
      stack_start(other.stack_start),
      mem_end(other.mem_end),
      symbols(other.symbols),
      file_name(other.file_name),
      tool_path_(other.tool_path_),
      execute_fn(other.execute_fn),
      wx_sighandler(other.wx_sighandler),
      remix_registers(other.remix_registers),
      remix_rcb(other.remix_rcb),
      remix_target_registers(other.remix_target_registers),
      remix_target_rcb(other.remix_target_rcb),
      remix_sighandler_state(other.remix_sighandler_state),
      remix_crash_handler(other.remix_crash_handler),
      remix_enable_stack_extension(other.remix_enable_stack_extension),
      modified_ranges(other.modified_ranges),
      saved_before_write_data(other.saved_before_write_data),
      last_saved_before_write_source(other.last_saved_before_write_source),
      last_saved_before_write_data(other.last_saved_before_write_data),
      last_saved_before_write_data_len(other.last_saved_before_write_data_len),
      module_flags(other.module_flags),
      init_cookie(other.init_cookie),
      last_stop_reason(other.last_stop_reason),
      need_to_call_did_fork_child(true),
      in_call(false) {
  if (other.in_call) {
    FATAL() << "Other can't be in a call";
  }
}

RemixModule::~RemixModule() {
  if (!modified_ranges.empty()) {
    FATAL() << "Some modified ranges not flushed";
  }
  if (host) {
    host->notify_remix_module_detach(this);
  }
}

static uint32_t remix_execute_flags(uint32_t mode,
                                    RemixModule::SinglestepMode step,
                                    RemixModule::TargetMatchMode match) {
  switch (step) {
    case RemixModule::SINGLESTEP:
      mode |= STOP_SINGLESTEP;
      break;
    case RemixModule::SINGLESTEP_FAST_FORWARD:
      mode |= STOP_SINGLESTEP_FAST_FORWARD;
      break;
    default:
      break;
  }
  switch (match) {
    case RemixModule::MATCH_IP_ONLY:
      mode |= STOP_MATCH_IGNORE_GP_REGS;
      break;
    default:
      break;
  }
  return mode;
}

StopReason RemixModule::execute_to_syscall(ReplayTask* t, SinglestepMode step) {
  return execute_helper(t, remix_execute_flags(STOP_AT_SYSCALL, step, MATCH_GP_REGS),
                        t->regs(), 0);
}

StopReason RemixModule::execute_to_ip(ReplayTask* t, remote_code_ptr ip,
                                      SinglestepMode step) {
  Registers r = t->regs();
  r.set_ip(ip);
  return execute_helper(t, remix_execute_flags(STOP_AT_IP, step, MATCH_GP_REGS), r, 0);
}

StopReason RemixModule::execute_to_breakpoint_fault(ReplayTask* t, remote_code_ptr ip,
                                                    SinglestepMode step) {
  Registers r = t->regs();
  r.set_ip(ip);
  return execute_helper(t, remix_execute_flags(STOP_AT_BREAKPOINT_FAULT, step, MATCH_GP_REGS), r, 0);
}

StopReason RemixModule::execute_emulate_ip(ReplayTask* t, remote_code_ptr ip,
                                           SinglestepMode step) {
  Registers r = t->regs();
  r.set_ip(ip);
  return execute_helper(t, remix_execute_flags(STOP_AT_IP_EMULATE, step, MATCH_GP_REGS), r, 0);
}

StopReason RemixModule::execute_to_target(ReplayTask* t, const Registers& regs,
                                          Ticks ticks, SinglestepMode step,
                                          TargetMatchMode match) {
  return execute_helper(t, remix_execute_flags(STOP_AT_TARGET, step, match), regs,
                        ticks);
}

vector<uint8_t> RemixModule::sync_reg_state(ReplayTask* t) {
  auto raw_reg = t->regs().get_ptrace_for_arch(t->arch());
  t->write_mem(remix_registers, raw_reg.data(), raw_reg.size());
  t->write_mem(remix_rcb, uint64_t(t->tick_count()));
  return raw_reg;
}

StopReason RemixModule::execute_helper(ReplayTask* t, uint32_t flags,
                                       const Registers& target_regs,
                                       Ticks target_ticks) {
  t->activate_preload_thread_locals();

  ASSERT(t,
         execute_fn && remix_registers && remix_rcb && remix_target_registers &&
             remix_target_rcb);
  ASSERT(t, t->vm()->all_watchpoints().empty())
      << "Remix execution does not support watchpoints";

  if (need_to_call_did_fork_child) {
    flush_modified_ranges(t);
    remote_code_ptr fn = find_code_symbol("remix_did_fork_child");
    auto remix_uid = to_remix_uid(t->vm()->uid());
    call(t, fn, &remix_uid, t->trace_reader().time());
    need_to_call_did_fork_child = false;
  } else {
    flush_other_process_modified_ranges(t);
  }
  if (host) {
    // Flush any pending unmap/map operations now so that the host can issue
    // its updates with those notifications already applied. A map operation
    // often includes an implicit unmap of the same area, and we don't want the
    // tool to see that and think that a notification related to the new map
    // has been subject to an unmap.
    flush_modified_ranges(t);
    host->will_change_state(t, this);
  } else if (modified_ranges.size() > 1000 ||
             saved_before_write_data.size() > saved_before_write_size - page_size()) {
    // Avoid stack overflow below
    flush_modified_ranges(t);
  } else {
    apply_saved_before_write_data(t, modified_ranges);
  }

  t->maybe_restart_syscall();

  auto raw_reg = sync_reg_state(t);
  auto stop_at = flags & STOP_AT_MASK;
  if (stop_at == STOP_AT_IP || stop_at == STOP_AT_IP_EMULATE ||
      stop_at == STOP_AT_TARGET || stop_at == STOP_AT_BREAKPOINT_FAULT) {
    auto raw_reg = target_regs.get_ptrace_for_arch(t->arch());
    t->write_mem(remix_target_registers, raw_reg.data(), raw_reg.size());
    if (stop_at == STOP_AT_TARGET) {
      t->write_mem(remix_target_rcb, uint64_t(target_ticks));
    }
  }

  // Don't let the AC flag leak in where it might blow up a remix tool.
  Registers r = t->regs();
  if (r.x86_alignmentcheck_flag()) {
    r.clear_x86_alignmentcheck_flag();
    t->set_regs(r);
  }

  last_stop_reason = (StopReason)call(
      t, execute_fn, flags, modified_ranges, modified_ranges.size(), t->rec_tid,
      t->tuid().serial(), t->trace_reader().time());
  modified_ranges.clear();
  saved_before_write_data.clear();

  t->read_bytes_helper(remix_registers, raw_reg.size(), raw_reg.data());
  r = t->regs();
  r.set_from_ptrace_for_arch(t->arch(), raw_reg.data(), raw_reg.size());
  // If we used ptrace singlestepping to help debug the remix code, the
  // TF flag might have been set in remix_registers.eflags.
  r.clear_x86_singlestep_flag();
  t->set_regs(r);
  t->set_tick_count(t->read_mem(remix_rcb));

  return last_stop_reason;
}

void RemixModule::will_change_state_without_execution(ReplayTask* t) {
  remote_code_ptr will_change_fn = find_code_symbol("remix_will_change_state");
  if (will_change_fn) {
    flush_modified_ranges(t);
    sync_reg_state(t);
    call(t, will_change_fn, t->rec_tid, t->tuid().serial(),
         t->trace_reader().time());
  }
  if (host) {
    host->will_change_state(t, this);
  }
}

void RemixModule::did_complete_execve(ReplayTask* t) {
  will_change_state_without_execution(t);
}

void RemixModule::set_log_modules(ReplayTask* t, uint32_t modules) {
  remote_ptr<void> remix_log_modules = find_symbol("remix_log_modules");
  if (remix_log_modules) {
    t->write_mem(remix_log_modules.cast<uint32_t>(), modules);
  }
}

void RemixModule::set_log_modules_from_environment(ReplayTask* t) {
  uint32_t modules = 0;
  if (get_log_level("remix-all") >= LOG_info) {
    modules |= REMIX_LOG_ALL;
  }
  if (get_log_level("remix-tool") >= LOG_info) {
    modules |= REMIX_LOG_TOOL;
  }
  if (get_log_level("remix-exec") >= LOG_info) {
    modules |= REMIX_LOG_EXEC;
  }
  if (get_log_level("remix-gen") >= LOG_info) {
    modules |= REMIX_LOG_GEN;
  }
  if (get_log_level("remix") >= LOG_info) {
    modules |= REMIX_LOG;
  }
  set_log_modules(t, modules);
}

MemoryRange RemixModule::memory_range() const {
  return MemoryRange(mem_base - page_size(), mem_end + page_size());
}

string RemixModule::gdb_helpers() const {
  stringstream ss;
  ss << "add-symbol-file " << file_name << " -o " << HEX(mem_base.as_int());
  return ss.str();
}

remote_ptr<void> RemixModule::find_symbol(const char* symbol) const {
  auto it = symbols.find(string(symbol));
  return it == symbols.end() ? nullptr : it->second;
}

remote_code_ptr RemixModule::find_code_symbol(const char* symbol) const {
  remote_ptr<void> p = find_symbol(symbol);
  return p.is_null() ? remote_code_ptr() : remote_code_ptr(p.as_int());
}

static const uintptr_t remix_call_return_address = 9;

static int64_t read_watch(ReplayTask* t) {
  if (!watch_addr) {
    return -12345;
  }
  bool ok = true;
  int64_t val = t->read_mem(remote_ptr<int64_t>(watch_addr), &ok);
  return ok ? val : -1234;
}

void RemixModule::handle_structured_remix_error(ReplayTask* t) const {
  auto remix_error_details = find_symbol("remix_error_details").cast<RemixErrorDetails>();
  if (!remix_error_details) {
    return;
  }
  auto details = t->read_mem(remix_error_details);
  if (details.code == REMIX_ERROR_INSTRUCTION_UNSUPPORTED_FOR_REPLAY) {
    STRUCTURED_FATAL("InstructionUnsupportedForReplay").task(t).instruction_address(t, details.pc)
      .disassembly(details.disassembly)
      << "Instruction not supported for replay: " << details.disassembly;
  }
  if (details.code == REMIX_ERROR_INSTRUCTION_UNSUPPORTED_ON_THIS_CPU) {
    STRUCTURED_FATAL("InstructionUnsupportedOnThisCpu").task(t).instruction_address(t, details.pc)
      .disassembly(details.disassembly).instruction_family(details.instruction_family)
      << "Instruction not supported on this CPU: " << details.disassembly;
  }
  if (details.code == REMIX_ERROR_INSTRUCTION_UNSUPPORTED_FOR_REMIX) {
    STRUCTURED_FATAL("InstructionUnsupportedForRemix").task(t).instruction_address(t, details.pc)
      .disassembly(details.disassembly)
      << "Instruction not supported for remix: " << details.disassembly;
  }
  if (details.code == REMIX_ERROR_FIVE_LEVEL_PAGE_TABLES_UNSUPPORTED) {
    STRUCTURED_FATAL("FiveLevelPageTablesNotSupported").task(t);
  }
}

intptr_t RemixModule::call_helper(ReplayTask* t, remote_code_ptr ip,
                                  const vector<intptr_t>& params,
                                  vector<uint8_t>& stack_data) const {
  if (!t->session().is_alive()) {
    LOG(info) << "Skipping remix call into dying task";
    return 0;
  }
  in_call = true;

  Registers r = t->regs();
  Registers saved_regs = r;
  remote_ptr<void> expected_final_sp;
  switch (t->arch()) {
    case x86_64: {
      // We don't support passing parameters on the stack yet
      ASSERT(t, params.size() <= 6);
      for (size_t i = 0; i < params.size(); ++i) {
        r.set_call_arg(i + 1, params[i]);
      }
      remote_ptr<void> sp = mem_end - stack_data.size();
      // x86-64 requires start of parameter area to be aligned to 16 bytes
      sp -= sp.as_int() & 15;
      expected_final_sp = sp;
      insert_data(stack_data, &remix_call_return_address,
                  sizeof(remix_call_return_address), 8);
      sp -= 8;
      t->write_bytes_helper(sp, stack_data.size(), stack_data.data());
      r.set_sp(sp);
      r.set_ip(ip);
      break;
    }
    default:
      FATAL() << "Unsupported arch";
  }
  // if the value in the syscall result register is ERESTARTSYS from some
  // interrupted system call, then when we resume execution the kernel may
  // misidentify this as a syscall restart, and decrement the program counter
  // by the size of a syscall instruction. Prevent that by always clearing
  // the syscall result here. This doesn't interefere with tracee application
  // registers because those are communicated via remix_registers.
  r.set_syscall_result(0);
  t->set_regs(r);

  vector<MemoryRange> unmaps;
  while (true) {
    if (singlestep_at &&
        (singlestep_at < 0 || t->trace_reader().time() == singlestep_at)) {
      Ticks tick_count = t->read_mem(remix_rcb);
      int64_t watch_val = -5678;
      do {
        t->resume_execution(RESUME_SINGLESTEP, RESUME_WAIT, RESUME_NO_TICKS, 0);
        Ticks new_tick_count = t->read_mem(remix_rcb);
        int64_t new_watch_val = read_watch(t);
        if (((!show_only_ticks || new_tick_count > tick_count) &&
             (show_module_steps || t->ip().to_data_ptr<void>() >= module_end)) ||
            (watch_addr && watch_val != new_watch_val)) {
          if (watch_val != new_watch_val) {
            fprintf(stderr, "watch:%llx\n", (long long)new_watch_val);
          }
          fprintf(stderr, "pid:%d ", t->tgid());
          t->regs().print_register_file_compact(stderr);
          fputc(' ', stderr);
          t->extra_regs().print_register_file_compact(stderr);
          fprintf(stderr, " ticks:%" PRId64 "\n", new_tick_count);
        }
        watch_val = new_watch_val;
        tick_count = new_tick_count;
      } while (t->stop_sig() == SIGTRAP);
    } else {
      t->resume_execution(RESUME_CONT, RESUME_WAIT, RESUME_NO_TICKS, 0);
    }
    switch (t->stop_sig()) {
      case SIGSEGV:
        if (try_handle_segfault(t, &unmaps)) {
          continue;
        }
        break;
      case SIGTRAP:
      case SIGFPE:
      case SIGBUS:
      case SIGILL:
        if (try_handle_crash(t)) {
          continue;
        }
        break;
    }
    break;
  }

  // Check that we exited with a SIGSEGV caused by returning from the function.
  if (t->stop_sig() == SIGSEGV) {
    // ... nothing to do
  } else if (t->stop_sig()) {
    stringstream extra;
    switch (t->stop_sig()) {
      case SIGILL: {
        extra << "; code";
        uint8_t buf[128];
        ssize_t bytes = t->read_bytes_fallible(t->ip().to_data_ptr<void>(), sizeof(buf), buf);
        if (bytes <= 0) {
          extra << " <unknown>";
        } else {
          for (ssize_t i = 0; i < bytes; ++i) {
            extra << " " << HEX(buf[i]);
          }
        }
        break;
      }
      case SIGABRT:
        handle_structured_remix_error(t);
        break;
    }
    ASSERT(t, false)
        << " remix produced rogue status " << t->status() << " at " << t->ip()
        << "; siginfo " << t->get_siginfo() << extra.str();
  } else {
    // Don't call t->get_siginfo() if there's no pending signal, it fails
    ASSERT(t, false)
        << " remix produced rogue status " << t->status() << " at " << t->ip();
  }
  ASSERT(t, t->regs().ip().register_value() == remix_call_return_address)
      << " remix got SIGSEGV at ip " << t->ip() << ", expected "
      << remix_call_return_address << "; siginfo " << t->get_siginfo();
  ASSERT(t, t->regs().sp() == expected_final_sp)
      << " remix got SIGSEGV with sp " << t->regs().sp() << ", expected "
      << expected_final_sp << "; siginfo " << t->get_siginfo();

  for (auto& m : unmaps) {
    AutoRemoteSyscalls remote(t, AutoRemoteSyscalls::DISABLE_MEMORY_PARAMS);
    remote.infallible_syscall(syscall_number_for_munmap(t->arch()),
        m.start(), m.size());
    t->vm()->unmap(t, m.start(), m.size());
  }

  intptr_t result = t->regs().syscall_result_signed();
  t->set_regs(saved_regs);
  in_call = false;
  return result;
}

bool RemixModule::try_handle_segfault(ReplayTask* t,
                                      vector<MemoryRange>* unmaps) const {
  auto ip_value = t->regs().ip().register_value();
  if (ip_value == remix_call_return_address) {
    return false;
  }
  if (ip_value == HANDLE_UNRECORDED_CPUID_FAULT_ADDRESS) {
    // If the trace was recorded with CPUID faulting, we should never do this
    // because we should always stop at CPUID instructions before executing them.
    ASSERT(t, !t->session().trace_reader().uses_cpuid_faulting());
    t->session().handle_unrecorded_cpuid_fault(t,
      ReplaySession::StepConstraints(RUN_CONTINUE));
    Registers regs = t->regs();
    regs.set_ip(regs.r8());
    t->set_regs(regs);
    return true;
  }

  // Before doing anything that cares about the state of memory, ensure that if
  // we were processing a syscallbuf flush our VM records are current.
  t->session().ensure_mprotect_records_up_to_date();

  // Use kernel_abi to avoid odd inconsistencies between distros
  auto arch_si =
      reinterpret_cast<const NativeArch::siginfo_t*>(&t->get_siginfo());
  auto addr = arch_si->_sifields._sigfault.si_addr_.rptr();
  return try_handle_wx(t, addr) ||
      try_handle_growdown(t, addr, unmaps) ||
      try_handle_crash(t);
}

bool RemixModule::try_handle_wx(ReplayTask* t,
                                remote_ptr<void> addr) const {
  if (!t->vm()->has_mapping(addr)) {
    return false;
  }
  const KernelMapping& km = t->vm()->mapping_of(floor_page_size(addr)).map;
  if ((km.prot() & (PROT_WRITE | PROT_EXEC)) != (PROT_WRITE | PROT_EXEC)) {
    return false;
  }

  LOG(debug) << "Handling WX fault at " << addr;

  RemixSighandlerState state;
  state.fault_address = addr.as_int();
  state.saved_pc = t->ip().register_value();
  state.signal = SIGSEGV;
  t->write_mem(remix_sighandler_state, state);

  Registers r = t->regs();
  r.set_ip(wx_sighandler);
  t->set_regs(r);

  return true;
}

bool RemixModule::try_handle_growdown(ReplayTask* t,
                                      remote_ptr<void> addr,
                                      vector<MemoryRange>* unmaps) const {
  if (!remix_enable_stack_extension || t->vm()->has_mapping(addr)) {
    return false;
  }
  auto maps = t->vm()->maps_starting_at(floor_page_size(addr));
  auto it = maps.begin();
  if (it == maps.end()) {
    return false;
  }
  const KernelMapping& km = it->map;
  if (!(km.flags() & MAP_GROWSDOWN)) {
    return false;
  }
  if (addr >= page_size() && t->vm()->has_mapping(addr - page_size())) {
    return false;
  }

  if (!t->read_mem(remix_enable_stack_extension)) {
    return false;
  }

  LOG(debug) << "Handling growdown fault at " << addr;

  auto new_start = floor_page_size(addr);
  size_t new_size = km.start() - new_start;
  {
    AutoRemoteSyscalls remote(t, AutoRemoteSyscalls::DISABLE_MEMORY_PARAMS);
    remote.infallible_mmap_syscall_if_alive(new_start, new_size, km.prot(),
        (km.flags() & ~MAP_GROWSDOWN) | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  }
  // Register the mapping so that future try_handle_segfaults will get the
  // correct view of memory.
  t->vm()->map(t, new_start, new_size, km.prot(),
               km.flags() | MAP_ANONYMOUS, 0, string(),
               KernelMapping::NO_DEVICE, KernelMapping::NO_INODE);
  unmaps->push_back(MemoryRange(new_start, new_size));

  return true;
}

bool RemixModule::try_handle_crash(ReplayTask* t) const {
  if (!remix_crash_handler) {
    return false;
  }
  remote_code_ptr handler = t->read_mem(remix_crash_handler);
  if (!handler) {
    return false;
  }
  auto arch_si =
      reinterpret_cast<const NativeArch::siginfo_t*>(&t->get_siginfo());
  auto addr = arch_si->_sifields._sigfault.si_addr_.rptr();

  LOG(debug) << "Handling crash fault at " << addr;

  RemixSighandlerState state;
  state.fault_address = addr.as_int();
  state.saved_pc = t->ip().register_value();
  state.signal = t->stop_sig();
  t->write_mem(remix_sighandler_state, state);

  Registers r = t->regs();
  r.set_ip(handler);
  t->set_regs(r);

  return true;
}

void RemixModule::flush_other_process_modified_ranges(ReplayTask* t) {
  AddressSpace* dirty = t->session().find_address_space(
      t->session().remix_module_with_modified_ranges());
  if (dirty && dirty != t->vm().get()) {
    ASSERT(t, !dirty->task_set().empty());
    ReplayTask* other = static_cast<ReplayTask*>(dirty->first_running_task());
    dirty->remix_module()->flush_modified_ranges(other);
  }
  t->session().set_remix_module_with_modified_ranges(AddressSpaceUid());
}

bool sort_writes_to_end(const ModifiedRangeAndProt& p1, const ModifiedRangeAndProt& p2) {
  return p1.change_type != MEM_WRITE && p2.change_type == MEM_WRITE;
}

const int HAS_DATA_OFFSET = 1;

void RemixModule::apply_saved_before_write_data(ReplayTask* t, vector<ModifiedRangeAndProt>& v) {
  remote_ptr<void> saved = saved_before_write_start;
  for (auto& m : v) {
    if (m.saved_before_write_data) {
      size_t len = m.end - m.start;
      t->write_bytes_helper(saved, len,
        saved_before_write_data.data() + m.saved_before_write_data - HAS_DATA_OFFSET);
      // Change the meaning of the field from "index within saved_before_write_data"
      // to "pointer value"
      m.saved_before_write_data = saved.as_int();
      saved += len;
    }
  }
}

void RemixModule::send_modified_ranges_notifications(ReplayTask* t, remote_code_ptr notify_fn,
                                                     vector<ModifiedRangeAndProt>& v) {
  apply_saved_before_write_data(t, v);
  call(t, notify_fn, v, v.size());
  v.clear();
}

void RemixModule::flush_modified_ranges(ReplayTask* t) {
  flush_other_process_modified_ranges(t);

  remote_code_ptr notify_fn = find_code_symbol("remix_notify_modified_ranges");
  if (notify_fn) {
    // Must be stable to preserve operation ordering
    stable_sort(modified_ranges.begin(), modified_ranges.end(), sort_writes_to_end);
    // Now coalesce notifications when possible.
    // Split notifications into chunks to avoid stack overflow.
    vector<ModifiedRangeAndProt> tmp;
    size_t total_saved_before_writes_len = 0;
    size_t saved_before_write_avail = saved_before_write_size - page_size();
    for (size_t i = 0; i < modified_ranges.size(); ++i) {
      auto& m = modified_ranges[i];
      size_t saved_data_size = m.saved_before_write_data ? m.end - m.start : 0;
      if (i + 1 < modified_ranges.size() && tmp.size() < 1000 &&
          total_saved_before_writes_len + saved_data_size <= saved_before_write_avail) {
        tmp.push_back(m);
        total_saved_before_writes_len += saved_data_size;
        continue;
      }
      if (total_saved_before_writes_len + saved_data_size <= saved_before_write_avail) {
        tmp.push_back(m);
        send_modified_ranges_notifications(t, notify_fn, tmp);
      } else {
        if (!tmp.empty()) {
          send_modified_ranges_notifications(t, notify_fn, tmp);
        }
        while (m.start < m.end) {
          ModifiedRangeAndProt mm = m;
          if (mm.end - mm.start > saved_before_write_avail) {
            mm.end = mm.start + saved_before_write_avail;
          }
          m.start = mm.end;
          m.saved_before_write_data += mm.end - mm.start;
          tmp.push_back(mm);
          send_modified_ranges_notifications(t, notify_fn, tmp);
        }
      }
    }
  }
  modified_ranges.clear();
  saved_before_write_data.clear();
}

void RemixModule::notify_memory_change(ReplayTask* t, const MemoryRange& range,
                                       int prot, MemChangeType change_type,
                                       size_t saved_before_write_offset) {
  // Ignore changes to remix_module data.
  if (memory_range().contains(range)) {
    return;
  }
  assert(!memory_range().intersects(range));

  flush_other_process_modified_ranges(t);
  t->session().set_remix_module_with_modified_ranges(t->vm()->uid());

  // XXX batching ranges here means that if some range is written, then
  // an overlapping range is written, remix modules might look for the new
  // data for the first range and see the new data for the second range. Does
  // this matter?

  modified_ranges.push_back({ range.start().as_int(), range.end().as_int(),
                              saved_before_write_offset,
                              t->trace_reader().time(), prot, change_type });
}

void RemixModule::notify_will_write(ReplayTask* t, const MemoryRange& range) {
  // Ignore pending changes to remix_module data.
  if (!(module_flags & MODULE_NEEDS_NOTIFY_WILL_WRITE_RANGE) ||
      memory_range().contains(range)) {
    return;
  }
  ASSERT(t, !last_saved_before_write_data)
      << "Previous will_write not matched with write?";

  size_t saved_before_write_len = saved_before_write_data.size();
  saved_before_write_data.resize(saved_before_write_len + range.size());
  ssize_t len = t->read_bytes_fallible(range.start(), range.size(),
      saved_before_write_data.data() + saved_before_write_len);
  if (len >= 0) {
    saved_before_write_data.resize(saved_before_write_len + len);

    last_saved_before_write_source = range.start();
    last_saved_before_write_data = saved_before_write_len + HAS_DATA_OFFSET;
    last_saved_before_write_data_len = len;
  }
}

void RemixModule::notify_written(ReplayTask* t, const MemoryRange& range) {
  // Ignore changes to remix_module data.
  if (memory_range().contains(range)) {
    return;
  }
  if (last_saved_before_write_source) {
    ASSERT(t, last_saved_before_write_source == range.start())
        << "notify_will_write does not match following notify_written";
    ASSERT(t, last_saved_before_write_data_len >= range.size())
        << "insufficient data saved before write";
  }
  notify_memory_change(t, range, -1, MEM_WRITE, last_saved_before_write_data);
  last_saved_before_write_data = 0;
  last_saved_before_write_data_len = 0;
  last_saved_before_write_source = nullptr;
}

void RemixModule::notify_will_exec(ReplayTask* t) {
  flush_modified_ranges(t);
  remote_code_ptr exec_fn = find_code_symbol("remix_exec");
  if (exec_fn) {
    call(t, exec_fn, t->trace_reader().time());
  }
}

void RemixModule::notify_will_exit(ReplayTask* t, bool early) {
  flush_modified_ranges(t);
  remote_code_ptr exit_fn = find_code_symbol("remix_will_exit");
  if (exit_fn) {
    uint32_t flags = 0;
    if (early) {
      flags |= REMIX_EXIT_SYNTHETIC;
    } else if (t->vm()->task_set().size() == 1) {
      flags |= REMIX_EXIT_LAST_THREAD;
      if (t->session().vms().size() == 1) {
        flags |= REMIX_EXIT_LAST_PROCESS;
      }
    }
    call(t, exit_fn, t->rec_tid, t->tuid().serial(), t->trace_reader().time(),
         flags);
  }
}

void RemixModule::notify_will_unmap(ReplayTask* t) {
  flush_modified_ranges(t);
  remote_code_ptr unmap_fn = find_code_symbol("remix_will_unmap");
  if (unmap_fn) {
    call(t, unmap_fn, t->rec_tid, t->tuid().serial(), t->trace_reader().time());
  }
}

void RemixModule::notify_remix_apply_quirk(ReplayTask* t, RemixQuirk quirk, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4, uintptr_t arg5) {
  remote_code_ptr apply_quirk_fn = find_code_symbol("remix_apply_quirk");
  if (apply_quirk_fn) {
    call(t, apply_quirk_fn, quirk, arg2, arg3, arg4, arg5);
  }
}

void RemixModule::flush_pending_state(ReplayTask* t) { flush_modified_ranges(t); }

} // namespace rr
