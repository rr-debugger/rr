/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "AddressSpace.h"

#include <limits.h>
#include <linux/kdev_t.h>
#include <linux/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <limits>

#include "rr/rr.h"

#include "preload/preload_interface.h"

#include "AutoRemoteSyscalls.h"
#include "MonitoredSharedMemory.h"
#include "RecordSession.h"
#include "RecordTask.h"
#include "Session.h"
#include "Task.h"
#include "core.h"
#include "log.h"

using namespace std;

namespace rr {

static const uint8_t x86_breakpoint_insn[] = { 0xcc }; // int $3
static const uint8_t arm64_breakpoint_insn[4] = {0x0, 0x0, 0x20, 0xd4}; // brk #0

static const uint8_t *breakpoint_insn(SupportedArch arch) {
  switch (arch) {
    case x86:
    case x86_64:
      return x86_breakpoint_insn;
    case aarch64:
      return arm64_breakpoint_insn;
    default:
      DEBUG_ASSERT(0 && "Must define breakpoint insn for this architecture");
      return nullptr;
  }
}


/**
 * Advance *str to skip leading blank characters.
 */
static const char* trim_leading_blanks(const char* str) {
  const char* trimmed = str;
  while (isblank(*trimmed)) {
    ++trimmed;
  }
  return trimmed;
}

/**
 * Returns true if a task in t's thread-group other than t is doing an exec.
 */
static bool thread_group_in_exec(Task* t) {
  if (!t->session().is_recording()) {
    return false;
  }
  for (Task* tt : t->thread_group()->task_set()) {
    if (tt == t) {
      continue;
    }
    RecordTask* rt = static_cast<RecordTask*>(tt);
    Event& ev = rt->ev();
    if (ev.is_syscall_event() &&
        is_execve_syscall(ev.Syscall().number, ev.Syscall().arch())) {
      return true;
    }
  }
  return false;
}

KernelMapIterator::KernelMapIterator(Task* t) : tid(t->tid) {
  // See https://lkml.org/lkml/2016/9/21/423
  ASSERT(t, !thread_group_in_exec(t)) << "Task-group in execve, so reading "
                                         "/proc/.../maps may trigger kernel "
                                         "deadlock!";
  init();
}

KernelMapIterator::~KernelMapIterator() {
  if (maps_file) {
    fclose(maps_file);
  }
}

void KernelMapIterator::init() {
  char maps_path[PATH_MAX];
  sprintf(maps_path, "/proc/%d/maps", tid);
  if (!(maps_file = fopen(maps_path, "r"))) {
    FATAL() << "Failed to open " << maps_path;
  }
  ++*this;
}

void KernelMapIterator::operator++() {
  char line[PATH_MAX * 2];
  if (!fgets(line, sizeof(line), maps_file)) {
    fclose(maps_file);
    maps_file = nullptr;
    return;
  }

  uint64_t start, end, offset, inode;
  int dev_major, dev_minor;
  char flags[32];
  int chars_scanned;
  int nparsed = sscanf(line, "%" SCNx64 "-%" SCNx64 " %31s %" SCNx64
                             " %x:%x %" SCNu64 " %n",
                       &start, &end, flags, &offset, &dev_major, &dev_minor,
                       &inode, &chars_scanned);
  DEBUG_ASSERT(8 /*number of info fields*/ == nparsed ||
               7 /*num fields if name is blank*/ == nparsed);

  // trim trailing newline, if any
  int last_char = strlen(line) - 1;
  if (line[last_char] == '\n') {
    line[last_char] = 0;
  }
  raw_line = line;

  const char* name = trim_leading_blanks(line + chars_scanned);
#if defined(__i386__)
  if (start > numeric_limits<uint32_t>::max() ||
      end > numeric_limits<uint32_t>::max() ||
      strcmp(name, "[vsyscall]") == 0) {
    // We manually read the exe link here because
    // this helper is used to set
    // |t->vm()->exe_image()|, so we can't rely on
    // that being correct yet.
    char proc_exe[PATH_MAX];
    char exe[PATH_MAX];
    snprintf(proc_exe, sizeof(proc_exe), "/proc/%d/exe", tid);
    ssize_t size = readlink(proc_exe, exe, sizeof(exe));
    if (size < 0) {
      FATAL() << "readlink failed";
    }
    FATAL() << "Sorry, tracee " << tid << " has x86-64 image " << exe
            << " and that's not supported with a 32-bit rr.";
  }
#endif
  int prot = (strchr(flags, 'r') ? PROT_READ : 0) |
             (strchr(flags, 'w') ? PROT_WRITE : 0) |
             (strchr(flags, 'x') ? PROT_EXEC : 0);
  int f = (strchr(flags, 'p') ? MAP_PRIVATE : 0) |
          (strchr(flags, 's') ? MAP_SHARED : 0);

  string tmp_name;
  if (strchr(name, '\\')) {
    // Unescape any '\012' sequences
    while (*name) {
      if (strncmp(name, "\\012", 4) == 0) {
        tmp_name.push_back('\n');
        name += 4;
      } else {
        tmp_name.push_back(*name);
        ++name;
      }
    }
    name = tmp_name.c_str();
  }

  km = KernelMapping(start, end, name, MKDEV(dev_major, dev_minor), inode, prot,
                     f, offset);
}

static KernelMapping read_kernel_mapping(pid_t tid, remote_ptr<void> addr) {
  MemoryRange range(addr, 1);
  for (KernelMapIterator it(tid); !it.at_end(); ++it) {
    const KernelMapping& km = it.current();
    if (km.contains(range)) {
      return km;
    }
  }
  return KernelMapping();
}

KernelMapping AddressSpace::read_kernel_mapping(Task* t,
                                                remote_ptr<void> addr) {
  return rr::read_kernel_mapping(t->tid, addr);
}

KernelMapping AddressSpace::read_local_kernel_mapping(uint8_t* addr) {
  return rr::read_kernel_mapping(getpid(), remote_ptr<void>((uintptr_t)addr));
}

/**
 * Cat the /proc/[t->tid]/maps file to stdout, line by line.
 */
void AddressSpace::print_process_maps(Task* t) {
  for (KernelMapIterator it(t); !it.at_end(); ++it) {
    string line;
    it.current(&line);
    cerr << line << '\n';
  }
}

AddressSpace::Mapping::Mapping(const KernelMapping& map,
                               const KernelMapping& recorded_map,
                               EmuFile::shr_ptr emu_file,
                               std::unique_ptr<struct stat> mapped_file_stat,
                               void* local_addr,
                               shared_ptr<MonitoredSharedMemory>&& monitored)
    : map(map),
      recorded_map(recorded_map),
      emu_file(emu_file),
      mapped_file_stat(move(mapped_file_stat)),
      local_addr(static_cast<uint8_t*>(local_addr)),
      monitored_shared_memory(move(monitored)),
      flags(FLAG_NONE) {}

static unique_ptr<struct stat> clone_stat(
    const unique_ptr<struct stat>& other) {
  return other ? unique_ptr<struct stat>(new struct stat(*other)) : nullptr;
}

AddressSpace::Mapping::Mapping(const Mapping& other)
    : map(other.map),
      recorded_map(other.recorded_map),
      emu_file(other.emu_file),
      mapped_file_stat(clone_stat(other.mapped_file_stat)),
      local_addr(other.local_addr),
      monitored_shared_memory(other.monitored_shared_memory),
      flags(other.flags) {}

AddressSpace::Mapping::~Mapping() {}

AddressSpace::~AddressSpace() {
  for (auto& m : mem) {
    if (m.second.local_addr) {
      int ret = munmap(m.second.local_addr, m.second.map.size());
      if (ret < 0) {
        FATAL() << "Can't munmap";
      }
    }
  }
  session_->on_destroy(this);
}

void AddressSpace::after_clone() { allocate_watchpoints(); }

static uint32_t find_offset_of_syscall_instruction_in(SupportedArch arch,
                                                      uint8_t* vdso_data,
                                                      size_t vdso_len) {
  auto instruction = syscall_instruction(arch);
  for (uint32_t i = 1; i < vdso_len - instruction.size(); ++i) {
    if (memcmp(vdso_data + i, instruction.data(), instruction.size()) == 0) {
      return i;
    }
  }
  return 0;
}

uint32_t AddressSpace::offset_to_syscall_in_vdso[SupportedArch_MAX + 1];

remote_code_ptr AddressSpace::find_syscall_instruction(Task* t) {
  SupportedArch arch = t->arch();
  // This assert passes even if --unmap-vdso is passed because this only ever
  // gets called at the start of process_execve before we unmap the vdso. After
  // the rr page is mapped in, we use the syscall instructions contained therein
  ASSERT(t, has_vdso()) << "Kernel with vDSO disabled?";
  if (!offset_to_syscall_in_vdso[arch]) {
    auto vdso_data = t->read_mem(vdso().start().cast<uint8_t>(), vdso().size());
    offset_to_syscall_in_vdso[arch] = find_offset_of_syscall_instruction_in(
        arch, vdso_data.data(), vdso_data.size());
    ASSERT(t, offset_to_syscall_in_vdso[arch])
        << "No syscall instruction found in VDSO";
  }
  return remote_code_ptr(
      (vdso().start().cast<uint8_t>() + offset_to_syscall_in_vdso[arch])
          .as_int());
}

static string find_rr_page_file(Task* t) {
  string path = resource_path() + "share/rr/rr_page_";
  switch (t->arch()) {
    case x86:
      path += "32";
      break;
    case x86_64:
      path += "64";
      break;
    case aarch64:
      path += "arm64";
      break;
    default:
      ASSERT(t, false) << "Unknown architecture";
      return path;
  }
  if (!t->session().is_recording()) {
    path += "_replay";
  }
  return path;
}

void AddressSpace::map_rr_page(AutoRemoteSyscalls& remote) {
  int prot = PROT_EXEC | PROT_READ;
  int flags = MAP_PRIVATE | MAP_FIXED;

  string file_name;
  Task* t = remote.task();
  SupportedArch arch = t->arch();

  string path = find_rr_page_file(t);

  {
    ScopedFd page(path.c_str(), O_RDONLY);
    ASSERT(t, page.is_open()) << "Failed to open rr_page file " << path;
    long child_fd = remote.send_fd(page.get());
    ASSERT(t, child_fd >= 0);
    remote.infallible_mmap_syscall(rr_page_start(), rr_page_size(), prot, flags,
                                   child_fd, 0);

    struct stat fstat = t->stat_fd(child_fd);
    file_name = t->file_name_of_fd(child_fd);

    remote.infallible_syscall(syscall_number_for_close(arch), child_fd);

    map(t, rr_page_start(), rr_page_size(), prot, flags, 0, file_name,
        fstat.st_dev, fstat.st_ino);
  }
  mapping_flags_of(rr_page_start()) = Mapping::IS_RR_PAGE;

  if (t->session().is_recording()) {
    // brk() will not have been called yet so the brk area is empty.
    brk_start = brk_end =
        remote.infallible_syscall(syscall_number_for_brk(arch), 0);
    ASSERT(t, !brk_end.is_null());
  }

  traced_syscall_ip_ = rr_page_syscall_entry_point(
      TRACED, UNPRIVILEGED, RECORDING_AND_REPLAY, t->arch());
  privileged_traced_syscall_ip_ = rr_page_syscall_entry_point(
      TRACED, PRIVILEGED, RECORDING_AND_REPLAY, t->arch());
}

void AddressSpace::unmap_all_but_rr_page(AutoRemoteSyscalls& remote) {
  vector<MemoryRange> unmaps;
  for (const auto& m : maps()) {
    // Do not attempt to unmap [vsyscall] --- it doesn't work.
    if (m.map.start() != AddressSpace::rr_page_start() &&
        m.map.start() != AddressSpace::preload_thread_locals_start() &&
        !m.map.is_vsyscall()) {
      unmaps.push_back(m.map);
    }
  }
  for (auto& m : unmaps) {
    remote.infallible_syscall(syscall_number_for_munmap(remote.task()->arch()),
                              m.start(), m.size());
    unmap(remote.task(), m.start(), m.size());
  }
}

/**
 * Must match generate_rr_page.py
 */
static const AddressSpace::SyscallType entry_points[] = {
  { AddressSpace::TRACED, AddressSpace::UNPRIVILEGED,
    AddressSpace::RECORDING_AND_REPLAY },
  { AddressSpace::TRACED, AddressSpace::PRIVILEGED,
    AddressSpace::RECORDING_AND_REPLAY },
  { AddressSpace::UNTRACED, AddressSpace::UNPRIVILEGED,
    AddressSpace::RECORDING_AND_REPLAY },
  { AddressSpace::UNTRACED, AddressSpace::UNPRIVILEGED,
    AddressSpace::REPLAY_ONLY },
  { AddressSpace::UNTRACED, AddressSpace::UNPRIVILEGED,
    AddressSpace::RECORDING_ONLY },
  { AddressSpace::UNTRACED, AddressSpace::PRIVILEGED,
    AddressSpace::RECORDING_AND_REPLAY },
  { AddressSpace::UNTRACED, AddressSpace::PRIVILEGED,
    AddressSpace::REPLAY_ONLY },
  { AddressSpace::UNTRACED, AddressSpace::PRIVILEGED,
    AddressSpace::RECORDING_ONLY },
  { AddressSpace::UNTRACED, AddressSpace::UNPRIVILEGED,
    AddressSpace::REPLAY_ASSIST },
};

static int rr_page_syscall_stub_size(SupportedArch arch) {
  int val = 0;
  switch (arch) {
    case x86:
    case x86_64:
      val = 3;
      break;
    case aarch64:
      val = 8;
      break;
    default:
      FATAL() << "Syscall stub size not defined for this architecture";
  }
  if (arch == NativeArch::arch()) {
    DEBUG_ASSERT(val == RR_PAGE_SYSCALL_STUB_SIZE);
  }
  return val;
}

static int rr_page_syscall_instruction_end(SupportedArch arch) {
  int val = 0;
  switch (arch) {
    case x86:
    case x86_64:
      val = 2;
      break;
    case aarch64:
      val = 4;
      break;
    default:
      FATAL() << "Syscall stub size not defined for this architecture";
  }
  if (arch == NativeArch::arch()) {
    DEBUG_ASSERT(val == RR_PAGE_SYSCALL_INSTRUCTION_END);
  }
  return val;
}

static remote_code_ptr entry_ip_from_index(SupportedArch arch, size_t i) {
  return remote_code_ptr(RR_PAGE_ADDR + rr_page_syscall_stub_size(arch) * i);
}

static remote_code_ptr exit_ip_from_index(SupportedArch arch, size_t i) {
  return remote_code_ptr(RR_PAGE_ADDR + rr_page_syscall_stub_size(arch) * i +
                         rr_page_syscall_instruction_end(arch));
}

remote_code_ptr AddressSpace::rr_page_syscall_exit_point(Traced traced,
                                                         Privileged privileged,
                                                         Enabled enabled,
                                                         SupportedArch arch) {
  for (auto& e : entry_points) {
    if (e.traced == traced && e.privileged == privileged &&
        e.enabled == enabled) {
      return exit_ip_from_index(arch, &e - entry_points);
    }
  }
  return nullptr;
}

remote_code_ptr AddressSpace::rr_page_syscall_entry_point(Traced traced,
                                                          Privileged privileged,
                                                          Enabled enabled,
                                                          SupportedArch arch) {
  for (auto& e : entry_points) {
    if (e.traced == traced && e.privileged == privileged &&
        e.enabled == enabled) {
      return entry_ip_from_index(arch, &e - entry_points);
    }
  }
  return nullptr;
}

const AddressSpace::SyscallType* AddressSpace::rr_page_syscall_from_exit_point(
    SupportedArch arch, remote_code_ptr ip) {
  for (size_t i = 0; i < array_length(entry_points); ++i) {
    if (exit_ip_from_index(arch, i) == ip) {
      return &entry_points[i];
    }
  }
  return nullptr;
}

const AddressSpace::SyscallType* AddressSpace::rr_page_syscall_from_entry_point(
    SupportedArch arch, remote_code_ptr ip) {
  for (size_t i = 0; i < array_length(entry_points); ++i) {
    if (entry_ip_from_index(arch, i) == ip) {
      return &entry_points[i];
    }
  }
  return nullptr;
}

vector<AddressSpace::SyscallType> AddressSpace::rr_page_syscalls() {
  vector<SyscallType> result;
  for (auto& e : entry_points) {
    result.push_back(e);
  }
  return result;
}

void AddressSpace::save_auxv(Task* t) {
  saved_auxv_ = read_auxv(t);
  save_interpreter_base(t, saved_auxv());
}

void AddressSpace::save_interpreter_base(Task* t, std::vector<uint8_t> auxv) {
  saved_interpreter_base_ = read_interpreter_base(auxv);
  save_ld_path(t, saved_interpreter_base());
}

void AddressSpace::save_ld_path(Task* t, remote_ptr<void> interpreter_base) {
  saved_ld_path_ = read_ld_path(t, interpreter_base);
}

void AddressSpace::read_mm_map(Task* t, struct prctl_mm_map* map) {
  char buf[PATH_MAX+1024];
  {
    string proc_stat = t->proc_stat_path();
    ScopedFd fd(proc_stat.c_str(), O_RDONLY);
    memset(buf, 0, sizeof(buf));
    int err = read_to_end(fd, 0, buf, sizeof(buf)-1);
    if (err < 0) {
      FATAL() << "Failed to read /proc/<pid>/stat";
    }
  }
  // The last close-paren indicates the end of the comm and the
  // start of the fixed-width area
  char* fixed = strrchr(buf, ')');
  // We don't change /proc/pid/exe, since we're unlikely to have CAP_SYS_ADMIN
  map->exe_fd = -1;
  // auxv is restored separately
  map->auxv = NULL;
  map->auxv_size = 0;
  // All of these fields of /proc/pid/stat, we don't use (currently)
  char state;
  pid_t ppid;
  pid_t pgrp;
  int session;
  int tty_nr;
  int tpgid;
  unsigned int flags;
  unsigned long minflt, cminflt, majflt, cmajflt, utime, stime;
  long cutime, cstime, priority, nice, num_threads, itrealvalue;
  unsigned long long starttime;
  unsigned long vsize;
  long rss;
  unsigned long rsslim, kstkesp, kstskip, signal;
  unsigned long blocked, sigignore, sigcatch, wchan, nswap, cnswap;
  int exit_signal, processor;
  unsigned int rt_priority, policy;
  unsigned long long delayacct_blkio_ticks;
  unsigned long guest_time;
  long cguest_time;
  int exit_code;
  // See the proc(5) man page for the correct scan codes for these
  size_t n = sscanf(fixed + 1,
    // state ppid pgrp session tty_nr tpgid
    " %c %d %d %d %d %d"
    // flags minflt cminflt majflt cmajflt utime stime cutime cstime
    " %u %lu %lu %lu %lu %lu %lu %ld %ld"
    // priority nice num_threads itrealvalue starttime vsize rss
    " %ld %ld %ld %ld %llu %lu %ld"
    // rsslim startcode endcode startstack kstkesp kstskip signal
    " %lu %lu %lu %lu %lu %lu %lu"
    // blocked sigignore sigcatch wchan nswap cnswap exit_signal
    " %lu %lu %lu %lu %lu %lu %d"
    // processor rt_priority policy delayacct_blkio_ticks guest_time cguest_time
    " %d %u %u %llu %lu %ld "
    // start_data end_data start_brk arg_start arg_end env_start env_end exit_code
    " %lu %lu %lu %lu %lu %lu %lu %d",
    &state, &ppid, &pgrp, &session, &tty_nr, &tpgid,
    &flags, &minflt, &cminflt, &majflt, &cmajflt, &utime, &stime, &cutime, &cstime,
    &priority, &nice, &num_threads, &itrealvalue, &starttime, &vsize, &rss,
    &rsslim, (unsigned long *)&map->start_code, (unsigned long *)&map->end_code,
    (unsigned long *)&map->start_stack, &kstkesp, &kstskip, &signal,
    &blocked, &sigignore, &sigcatch, &wchan, &nswap, &cnswap, &exit_signal,
    &processor, &rt_priority, &policy, &delayacct_blkio_ticks, &guest_time,
    &cguest_time, (unsigned long *)&map->start_data, (unsigned long *)&map->end_data,
    (unsigned long *)&map->start_brk, (unsigned long *)&map->arg_start,
    (unsigned long *)&map->arg_end, (unsigned long *)&map->env_start,
    (unsigned long *)&map->env_end, &exit_code);
  ASSERT(t, n == 50);
  // Fill in brk end
  ASSERT(t, map->start_brk == this->brk_start.as_int());
  map->brk = this->brk_end.as_int();
}

void AddressSpace::post_exec_syscall(Task* t) {
  // First locate a syscall instruction we can use for remote syscalls.
  traced_syscall_ip_ = find_syscall_instruction(t);
  privileged_traced_syscall_ip_ = nullptr;

  do_breakpoint_fault_addr_ = nullptr;
  stopping_breakpoint_table_ = nullptr;
  stopping_breakpoint_table_entry_size_ = 0;

  // Now remote syscalls work, we can open_mem_fd.
  t->open_mem_fd();

  // Set up AutoRemoteSyscalls again now that the mem-fd is open.
  AutoRemoteSyscalls remote(t);
  // Now we can set up the "rr page" at its fixed address. This gives
  // us traced and untraced syscall instructions at known, fixed addresses.
  map_rr_page(remote);
  // Set up the preload_thread_locals shared area.
  t->session().create_shared_mmap(remote, PRELOAD_THREAD_LOCALS_SIZE,
                                  preload_thread_locals_start(),
                                  "preload_thread_locals");
  mapping_flags_of(preload_thread_locals_start()) |=
      AddressSpace::Mapping::IS_THREAD_LOCALS;
}

void AddressSpace::brk(Task* t, remote_ptr<void> addr, int prot) {
  LOG(debug) << "brk(" << addr << ")";

  remote_ptr<void> old_brk = ceil_page_size(brk_end);
  remote_ptr<void> new_brk = ceil_page_size(addr);
  if (old_brk < new_brk) {
    map(t, old_brk, new_brk - old_brk, prot, MAP_ANONYMOUS | MAP_PRIVATE, 0,
        "[heap]");
  } else {
    unmap(t, new_brk, old_brk - new_brk);
  }
  brk_end = addr;
}

static const char* stringify_flags(int flags) {
  switch (flags) {
    case AddressSpace::Mapping::FLAG_NONE:
      return "";
    case AddressSpace::Mapping::IS_SYSCALLBUF:
      return " [syscallbuf]";
    case AddressSpace::Mapping::IS_THREAD_LOCALS:
      return " [thread_locals]";
    case AddressSpace::Mapping::IS_PATCH_STUBS:
      return " [patch_stubs]";
    default:
      return "[unknown_flags]";
  }
}

void AddressSpace::dump() const {
  fprintf(stderr, "  (heap: %p-%p)\n", (void*)brk_start.as_int(),
          (void*)brk_end.as_int());
  for (auto it = mem.begin(); it != mem.end(); ++it) {
    const KernelMapping& m = it->second.map;
    fprintf(stderr, "%s%s\n", m.str().c_str(),
            stringify_flags(it->second.flags));
  }
}

SupportedArch AddressSpace::arch() const {
  return (*task_set().begin())->arch();
}

BreakpointType AddressSpace::get_breakpoint_type_for_retired_insn(
    remote_code_ptr ip) {
  remote_code_ptr addr = ip.undo_executed_bkpt(arch());
  return get_breakpoint_type_at_addr(addr);
}

BreakpointType AddressSpace::get_breakpoint_type_at_addr(remote_code_ptr addr) {
  auto it = breakpoints.find(addr);
  return it == breakpoints.end() ? BKPT_NONE : it->second.type();
}

bool AddressSpace::is_breakpoint_in_private_read_only_memory(
    remote_code_ptr addr) {
  for (const auto& m : maps_containing_or_after(addr.to_data_ptr<void>())) {
    if (m.map.start() >=
        addr.increment_by_bkpt_insn_length(arch()).to_data_ptr<void>()) {
      break;
    }
    if ((m.map.prot() & PROT_WRITE) || (m.map.flags() & MAP_SHARED)) {
      return false;
    }
  }
  return true;
}

void AddressSpace::replace_breakpoints_with_original_values(
    uint8_t* dest, size_t length, remote_ptr<uint8_t> addr) {
  for (auto& it : breakpoints) {
    remote_ptr<uint8_t> bkpt_location = it.first.to_data_ptr<uint8_t>();
    remote_ptr<uint8_t> start = max(addr, bkpt_location);
    remote_ptr<uint8_t> end =
        min(addr + length, bkpt_location + bkpt_instruction_length(arch()));
    if (start < end) {
      memcpy(dest + (start - addr),
             it.second.original_data() + (start - bkpt_location), end - start);
    }
  }
}

bool AddressSpace::is_breakpoint_instruction(Task* t, remote_code_ptr ip) {
  bool ok = true;
  uint8_t data[MAX_BKPT_INSTRUCTION_LENGTH];
  t->read_bytes_helper(ip.to_data_ptr<uint8_t>(),
    bkpt_instruction_length(t->arch()), data, &ok);
  return memcmp(data, breakpoint_insn(t->arch()),
    bkpt_instruction_length(t->arch())) == 0 && ok;
}

static void remove_range(set<MemoryRange>& ranges, const MemoryRange& range) {
  if (ranges.empty()) {
    return;
  }

  auto start = ranges.lower_bound(range);
  // An earlier range might extend into range, so check for that.
  if (start != ranges.begin()) {
    --start;
    if (start->end() <= range.start()) {
      ++start;
    }
  }
  auto end = start;
  auto prev_end = start;
  while (end != ranges.end() && end->start() < range.end()) {
    prev_end = end;
    ++end;
  }
  if (start == end) {
    return;
  }
  MemoryRange start_range = *start;
  MemoryRange end_range = *prev_end;
  ranges.erase(start, end);
  if (start_range.start() < range.start()) {
    ranges.insert(MemoryRange(start_range.start(), range.start()));
  }
  if (range.end() < end_range.end()) {
    ranges.insert(MemoryRange(range.end(), end_range.end()));
  }
}

static void add_range(set<MemoryRange>& ranges, const MemoryRange& range) {
  // Remove overlapping ranges
  remove_range(ranges, range);
  ranges.insert(range);
  // We could coalesce adjacent ranges, but there's probably no need.
}

KernelMapping AddressSpace::map(Task* t, remote_ptr<void> addr,
                                size_t num_bytes, int prot, int flags,
                                off64_t offset_bytes, const string& fsname,
                                dev_t device, ino_t inode,
                                unique_ptr<struct stat> mapped_file_stat,
                                const KernelMapping* recorded_map,
                                EmuFile::shr_ptr emu_file, void* local_addr,
                                shared_ptr<MonitoredSharedMemory>&& monitored) {
  LOG(debug) << "mmap(" << addr << ", " << num_bytes << ", " << HEX(prot)
             << ", " << HEX(flags) << ", " << HEX(offset_bytes) << ")";
  num_bytes = ceil_page_size(num_bytes);
  KernelMapping m(addr, addr + num_bytes, fsname, device, inode, prot, flags,
                  offset_bytes);
  if (!num_bytes) {
    return m;
  }

  remove_range(dont_fork, MemoryRange(addr, num_bytes));
  remove_range(wipe_on_fork, MemoryRange(addr, num_bytes));

  // The mmap() man page doesn't specifically describe
  // what should happen if an existing map is
  // "overwritten" by a new map (of the same resource).
  // In testing, the behavior seems to be as if the
  // overlapping region is unmapped and then remapped
  // per the arguments to the second call.
  unmap_internal(t, addr, num_bytes);

  const KernelMapping& actual_recorded_map = recorded_map ? *recorded_map : m;
  map_and_coalesce(t, m, actual_recorded_map, emu_file, move(mapped_file_stat),
                   move(local_addr), move(monitored));

  // During an emulated exec, we will explicitly map in a (copy of) the VDSO
  // at the recorded address.
  if (actual_recorded_map.is_vdso()) {
    vdso_start_addr = addr;
  }

  return m;
}

template <typename Arch> void AddressSpace::at_preload_init_arch(Task* t) {
  auto params = t->read_mem(
      remote_ptr<rrcall_init_preload_params<Arch>>(t->regs().arg1()));

  if (t->session().is_recording()) {
    ASSERT(t,
           t->session().as_record()->use_syscall_buffer() ==
               params.syscallbuf_enabled)
        << "Tracee thinks syscallbuf is "
        << (params.syscallbuf_enabled ? "en" : "dis")
        << "abled, but tracer thinks "
        << (t->session().as_record()->use_syscall_buffer() ? "en" : "dis")
        << "abled";
  } else {
    if (params.breakpoint_table_entry_size == -1) {
      do_breakpoint_fault_addr_ = params.breakpoint_instr_addr.rptr().as_int();
    } else {
      stopping_breakpoint_table_ = params.breakpoint_table.rptr().as_int();
      stopping_breakpoint_table_entry_size_ =
          params.breakpoint_table_entry_size;
    }
  }

  if (!params.syscallbuf_enabled) {
    return;
  }

  syscallbuf_enabled_ = true;

  if (t->session().is_recording()) {
    monkeypatch_state->patch_at_preload_init(static_cast<RecordTask*>(t));
  }
}

void AddressSpace::at_preload_init(Task* t) {
  RR_ARCH_FUNCTION(at_preload_init_arch, t->arch(), t);
}

const AddressSpace::Mapping& AddressSpace::mapping_of(
    remote_ptr<void> addr) const {
  MemoryRange range(floor_page_size(addr), 1);
  auto it = mem.find(range);
  DEBUG_ASSERT(it != mem.end());
  DEBUG_ASSERT(it->second.map.contains(range));
  return it->second;
}
uint32_t& AddressSpace::mapping_flags_of(remote_ptr<void> addr) {
  return const_cast<AddressSpace::Mapping&>(
             static_cast<const AddressSpace*>(this)->mapping_of(addr))
      .flags;
}

uint8_t* AddressSpace::local_mapping(remote_ptr<void> addr, size_t size) {
  MemoryRange range(floor_page_size(addr), 1);
  auto it = mem.find(range);
  if (it == mem.end()) {
    return nullptr;
  }
  DEBUG_ASSERT(it->second.map.contains(range));
  const Mapping& map = it->second;
  // Fall back to the slow path if we can't get the entire region
  if (size > static_cast<size_t>(map.map.end() - addr)) {
    return nullptr;
  }
  if (map.local_addr != nullptr) {
    size_t offset = addr - map.map.start();
    return static_cast<uint8_t*>(map.local_addr) + offset;
  }
  return nullptr;
}

void* AddressSpace::detach_local_mapping(remote_ptr<void> addr) {
  auto m = const_cast<AddressSpace::Mapping&>(mapping_of(addr));
  void* p = m.local_addr;
  m.local_addr = nullptr;
  return p;
}

bool AddressSpace::has_mapping(remote_ptr<void> addr) const {
  if (addr + page_size() < addr) {
    // Assume the last byte in the address space is never mapped; avoid overflow
    return false;
  }
  MemoryRange m(floor_page_size(addr), 1);
  auto it = mem.find(m);
  return it != mem.end() && it->first.contains(m);
}

bool AddressSpace::has_rr_page() const {
  MemoryRange m(RR_PAGE_ADDR, 1);
  auto it = mem.find(m);
  return it != mem.end() && (it->second.flags & Mapping::IS_RR_PAGE);
}

void AddressSpace::protect(Task* t, remote_ptr<void> addr, size_t num_bytes,
                           int prot) {
  LOG(debug) << "mprotect(" << addr << ", " << num_bytes << ", " << HEX(prot)
             << ")";

  MemoryRange last_overlap;
  auto protector = [this, prot, &last_overlap](const Mapping& mm,
                                               const MemoryRange& rem) {
    LOG(debug) << "  protecting (" << rem << ") ...";

    Mapping m = move(mm);
    remove_from_map(m.map);

    // PROT_GROWSDOWN means that if this is a grows-down segment
    // (which for us means "stack") then the change should be
    // extended to the start of the segment.
    // We don't try to handle the analogous PROT_GROWSUP, because we
    // don't understand the idea of a grows-up segment.
    remote_ptr<void> new_start;
    if ((m.map.start() < rem.start()) && (prot & PROT_GROWSDOWN)) {
      new_start = m.map.start();
      LOG(debug) << "  PROT_GROWSDOWN: expanded region down to " << new_start;
    } else {
      new_start = rem.start();
    }

    LOG(debug) << "  erased (" << m.map << ")";

    // If the first segment we protect underflows the
    // region, remap the underflow region with previous
    // prot.
    auto monitored = m.monitored_shared_memory;
    if (m.map.start() < new_start) {
      Mapping underflow(
          m.map.subrange(m.map.start(), rem.start()),
          m.recorded_map.subrange(m.recorded_map.start(), rem.start()),
          m.emu_file, clone_stat(m.mapped_file_stat), m.local_addr,
          move(monitored));
      underflow.flags = m.flags;
      add_to_map(underflow);
    }
    // Remap the overlapping region with the new prot.
    remote_ptr<void> new_end = min(rem.end(), m.map.end());

    int new_prot = prot & (PROT_READ | PROT_WRITE | PROT_EXEC);
    Mapping overlap(
        m.map.subrange(new_start, new_end).set_prot(new_prot),
        m.recorded_map.subrange(new_start, new_end).set_prot(new_prot),
        m.emu_file, clone_stat(m.mapped_file_stat),
        m.local_addr ? m.local_addr + (new_start - m.map.start()) : 0,
        m.monitored_shared_memory
            ? m.monitored_shared_memory->subrange(new_start - m.map.start(),
                                                  new_end - new_start)
            : nullptr);
    overlap.flags = m.flags;
    add_to_map(overlap);
    last_overlap = overlap.map;

    // If the last segment we protect overflows the
    // region, remap the overflow region with previous
    // prot.
    if (rem.end() < m.map.end()) {
      Mapping overflow(
          m.map.subrange(rem.end(), m.map.end()),
          m.recorded_map.subrange(rem.end(), m.map.end()), m.emu_file,
          clone_stat(m.mapped_file_stat),
          m.local_addr ? m.local_addr + (rem.end() - m.map.start()) : 0,
          m.monitored_shared_memory
              ? m.monitored_shared_memory->subrange(rem.end() - m.map.start(),
                                                    m.map.end() - rem.end())
              : nullptr);
      overflow.flags = m.flags;
      add_to_map(overflow);
    }
  };
  for_each_in_range(addr, num_bytes, protector, ITERATE_CONTIGUOUS);
  if (last_overlap.size()) {
    // All mappings that we altered which might need coalescing
    // are adjacent to |last_overlap|.
    coalesce_around(t, mem.find(last_overlap));
  }
}

void AddressSpace::fixup_mprotect_growsdown_parameters(Task* t) {
  ASSERT(t, !(t->regs().arg3() & PROT_GROWSUP));
  if (t->regs().arg3() & PROT_GROWSDOWN) {
    Registers r = t->regs();
    if (r.arg1() == floor_page_size(r.arg1()) && has_mapping(r.arg1())) {
      auto& km = mapping_of(r.arg1()).map;
      if (km.flags() & MAP_GROWSDOWN) {
        auto new_start = km.start();
        r.set_arg2(remote_ptr<void>(r.arg1()) + size_t(r.arg2()) - new_start);
        r.set_arg1(new_start);
        r.set_arg3(r.arg3() & ~PROT_GROWSDOWN);
        t->set_regs(r);
      }
    }
  }
}

void AddressSpace::remap(Task* t, remote_ptr<void> old_addr,
                         size_t old_num_bytes, remote_ptr<void> new_addr,
                         size_t new_num_bytes) {
  LOG(debug) << "mremap(" << old_addr << ", " << old_num_bytes << ", "
             << new_addr << ", " << new_num_bytes << ")";
  old_num_bytes = ceil_page_size(old_num_bytes);

  Mapping mr = mapping_of(old_addr);
  DEBUG_ASSERT(!mr.monitored_shared_memory);
  KernelMapping km = mr.map.subrange(old_addr, min(mr.map.end(), old_addr + old_num_bytes));

  unmap_internal(t, old_addr, old_num_bytes);
  if (0 == new_num_bytes) {
    return;
  }
  new_num_bytes = ceil_page_size(new_num_bytes);

  auto it = dont_fork.lower_bound(MemoryRange(old_addr, old_num_bytes));
  if (it != dont_fork.end() && it->start() < old_addr + old_num_bytes) {
    // mremap fails if some but not all pages are marked DONTFORK
    DEBUG_ASSERT(*it == MemoryRange(old_addr, old_num_bytes));
    remove_range(dont_fork, MemoryRange(old_addr, old_num_bytes));
    add_range(dont_fork, MemoryRange(new_addr, new_num_bytes));
  } else {
    remove_range(dont_fork, MemoryRange(old_addr, old_num_bytes));
    remove_range(dont_fork, MemoryRange(new_addr, new_num_bytes));
  }

  it = wipe_on_fork.lower_bound(MemoryRange(old_addr, old_num_bytes));
  if (it != wipe_on_fork.end() && it->start() < old_addr + old_num_bytes) {
    // hopefully mremap fails if some but not all pages are marked DONTFORK
    DEBUG_ASSERT(*it == MemoryRange(old_addr, old_num_bytes));
    remove_range(wipe_on_fork, MemoryRange(old_addr, old_num_bytes));
    add_range(wipe_on_fork, MemoryRange(new_addr, new_num_bytes));
  } else {
    remove_range(wipe_on_fork, MemoryRange(old_addr, old_num_bytes));
    remove_range(wipe_on_fork, MemoryRange(new_addr, new_num_bytes));
  }

  unmap_internal(t, new_addr, new_num_bytes);

  remote_ptr<void> new_end = new_addr + new_num_bytes;
  map_and_coalesce(t, km.set_range(new_addr, new_end),
                   mr.recorded_map.set_range(new_addr, new_end), mr.emu_file,
                   clone_stat(mr.mapped_file_stat), nullptr, nullptr);
}

void AddressSpace::remove_breakpoint(remote_code_ptr addr,
                                     BreakpointType type) {
  auto it = breakpoints.find(addr);
  if (it == breakpoints.end() || it->second.unref(type) > 0) {
    return;
  }
  destroy_breakpoint(it);
}

bool AddressSpace::add_breakpoint(remote_code_ptr addr, BreakpointType type) {
  auto it = breakpoints.find(addr);
  if (it == breakpoints.end()) {
    uint8_t overwritten_data[MAX_BKPT_INSTRUCTION_LENGTH];
    ssize_t bkpt_size = bkpt_instruction_length(arch());
    // Grab a random task from the VM so we can use its
    // read/write_mem() helpers.
    Task* t = *task_set().begin();
    if (bkpt_size !=
        t->read_bytes_fallible(addr.to_data_ptr<uint8_t>(),
                               bkpt_size, overwritten_data)) {
      return false;
    }
    t->write_bytes_helper(addr.to_data_ptr<uint8_t>(), bkpt_size,
                 breakpoint_insn(arch()), nullptr,
                 Task::IS_BREAKPOINT_RELATED);

    auto it_and_is_new = breakpoints.insert(make_pair(addr, Breakpoint()));
    DEBUG_ASSERT(it_and_is_new.second);
    memcpy(it_and_is_new.first->second.overwritten_data,
      overwritten_data, sizeof(overwritten_data));
    it = it_and_is_new.first;
  }
  it->second.ref(type);
  return true;
}

void AddressSpace::remove_all_breakpoints() {
  while (!breakpoints.empty()) {
    destroy_breakpoint(breakpoints.begin());
  }
}

void AddressSpace::suspend_breakpoint_at(remote_code_ptr addr) {
  auto it = breakpoints.find(addr);
  if (it != breakpoints.end()) {
    Task* t = *task_set().begin();
    t->write_bytes_helper(addr.to_data_ptr<uint8_t>(),
      bkpt_instruction_length(arch()), it->second.overwritten_data);
  }
}

void AddressSpace::restore_breakpoint_at(remote_code_ptr addr) {
  auto it = breakpoints.find(addr);
  if (it != breakpoints.end()) {
    Task* t = *task_set().begin();
    t->write_bytes_helper(addr.to_data_ptr<uint8_t>(),
      bkpt_instruction_length(arch()),
      breakpoint_insn(arch()));
  }
}

int AddressSpace::access_bits_of(WatchType type) {
  switch (type) {
    case WATCH_EXEC:
      return EXEC_BIT;
    case WATCH_WRITE:
      return WRITE_BIT;
    case WATCH_READWRITE:
      return READ_BIT | WRITE_BIT;
    default:
      FATAL() << "Unknown watchpoint type " << type;
      return 0; // not reached
  }
}

/**
 * We do not allow a watchpoint to watch the last byte of memory addressable
 * by rr. This avoids constructing a MemoryRange that wraps around.
 * For 64-bit builds this is no problem because addresses at the top of memory
 * are in kernel space. For 32-bit builds it seems impossible to map the last
 * page of memory in Linux so we should be OK there too.
 * Note that zero-length watchpoints are OK. configure_watch_registers just
 * ignores them.
 */
static MemoryRange range_for_watchpoint(remote_ptr<void> addr,
                                        size_t num_bytes) {
  uintptr_t p = addr.as_int();
  uintptr_t max_len = UINTPTR_MAX - p;
  return MemoryRange(addr, min<uintptr_t>(num_bytes, max_len));
}

void AddressSpace::remove_watchpoint(remote_ptr<void> addr, size_t num_bytes,
                                     WatchType type) {
  auto it = watchpoints.find(range_for_watchpoint(addr, num_bytes));
  if (it != watchpoints.end() &&
      0 == it->second.unwatch(access_bits_of(type))) {
    watchpoints.erase(it);
  }
  allocate_watchpoints();
}

bool AddressSpace::add_watchpoint(remote_ptr<void> addr, size_t num_bytes,
                                  WatchType type) {
  MemoryRange key = range_for_watchpoint(addr, num_bytes);
  auto it = watchpoints.find(key);
  if (it == watchpoints.end()) {
    auto it_and_is_new =
        watchpoints.insert(make_pair(key, Watchpoint(num_bytes)));
    DEBUG_ASSERT(it_and_is_new.second);
    it = it_and_is_new.first;
    update_watchpoint_value(it->first, it->second);
  }
  it->second.watch(access_bits_of(type));
  return allocate_watchpoints();
}

void AddressSpace::save_watchpoints() {
  saved_watchpoints.push_back(watchpoints);
}

bool AddressSpace::restore_watchpoints() {
  DEBUG_ASSERT(!saved_watchpoints.empty());
  watchpoints = saved_watchpoints[saved_watchpoints.size() - 1];
  saved_watchpoints.pop_back();
  return allocate_watchpoints();
}

bool AddressSpace::update_watchpoint_value(const MemoryRange& range,
                                           Watchpoint& watchpoint) {
  Task* t = *task_set().begin();
  bool valid = true;
  vector<uint8_t> value_bytes = watchpoint.value_bytes;
  for (size_t i = 0; i < value_bytes.size(); ++i) {
    value_bytes[i] = 0xFF;
  }
  remote_ptr<void> addr = range.start();
  size_t num_bytes = range.size();
  while (num_bytes > 0) {
    ssize_t bytes_read = t->read_bytes_fallible(
        addr, num_bytes, value_bytes.data() + (addr - range.start()));
    if (bytes_read <= 0) {
      valid = false;
      // advance to next page and try to read more. We want to know
      // when the valid part of a partially invalid watchpoint changes.
      bytes_read =
          min<size_t>(num_bytes, (floor_page_size(addr) + page_size()) - addr);
    }
    addr += bytes_read;
    num_bytes -= bytes_read;
  }

  bool changed = valid != watchpoint.valid ||
                 memcmp(value_bytes.data(), watchpoint.value_bytes.data(),
                        value_bytes.size()) != 0;
  watchpoint.valid = valid;
  watchpoint.value_bytes = value_bytes;
  return changed;
}

void AddressSpace::update_watchpoint_values(remote_ptr<void> start,
                                            remote_ptr<void> end) {
  MemoryRange r(start, end);
  for (auto& it : watchpoints) {
    if (it.first.intersects(r) &&
        update_watchpoint_value(it.first, it.second)) {
      it.second.changed = true;
      // We do nothing to track kernel reads of read-write watchpoints...
    }
  }
}

static int DR_WATCHPOINT(int n) { return 1 << n; }

static bool watchpoint_triggered(uintptr_t debug_status,
                                 const vector<int8_t>& regs) {
  for (auto reg : regs) {
    if (debug_status & DR_WATCHPOINT(reg)) {
      return true;
    }
  }
  return false;
}

bool AddressSpace::notify_watchpoint_fired(uintptr_t debug_status,
    remote_ptr<void> hit_addr,
    remote_code_ptr address_of_singlestep_start) {
  bool triggered = false;
  for (auto& it : watchpoints) {
    // On Skylake/4.14.13-300.fc27.x86_64 at least, we have observed a
    // situation where singlestepping through the instruction before a hardware
    // execution watchpoint causes singlestep completion *and* also reports the
    // hardware execution watchpoint being triggered. The latter is incorrect.
    // This could be a HW issue or a kernel issue. Work around it by ignoring
    // triggered watchpoints that aren't on the instruction we just tried to
    // execute.
    bool write_triggered = (it.second.watched_bits() & WRITE_BIT) &&
        update_watchpoint_value(it.first, it.second);
    // Depending on the architecture the hardware may indicate hit watchpoints
    // either by number, or by the address that triggered the watchpoint hit
    // - support either.
    bool read_triggered = false;
    bool exec_triggered = false;
    bool watchpoint_in_range = false;
    if (is_x86ish(arch())) {
      read_triggered = (it.second.watched_bits() & READ_BIT) &&
        watchpoint_triggered(debug_status,
                             it.second.debug_regs_for_exec_read);
      exec_triggered = (it.second.watched_bits() & EXEC_BIT) &&
        (address_of_singlestep_start.is_null() ||
         it.first.start() == address_of_singlestep_start.to_data_ptr<void>()) &&
         watchpoint_triggered(debug_status,
                              it.second.debug_regs_for_exec_read);
    } else {
      watchpoint_in_range = it.first.contains(hit_addr);
    }
    if (write_triggered || read_triggered || exec_triggered || watchpoint_in_range) {
      it.second.changed = true;
      triggered = true;
    }
  }
  return triggered;
}

void AddressSpace::notify_written(remote_ptr<void> addr, size_t num_bytes,
                                  uint32_t flags) {
  if (!(flags & Task::IS_BREAKPOINT_RELATED)) {
    update_watchpoint_values(addr, addr + num_bytes);
  }
  session()->accumulate_bytes_written(num_bytes);
}

void AddressSpace::remove_all_watchpoints() {
  watchpoints.clear();
  allocate_watchpoints();
}

void AddressSpace::unmap(Task* t, remote_ptr<void> addr, ssize_t num_bytes) {
  LOG(debug) << "munmap(" << addr << ", " << num_bytes << ")";
  num_bytes = ceil_page_size(num_bytes);
  if (!num_bytes) {
    return;
  }

  remove_range(dont_fork, MemoryRange(addr, num_bytes));
  remove_range(wipe_on_fork, MemoryRange(addr, num_bytes));

  return unmap_internal(t, addr, num_bytes);
}

void AddressSpace::unmap_internal(Task*, remote_ptr<void> addr,
                                  ssize_t num_bytes) {
  LOG(debug) << "munmap(" << addr << ", " << num_bytes << ")";

  auto unmapper = [this](const Mapping& mm, const MemoryRange& rem) {
    LOG(debug) << "  unmapping (" << rem << ") ...";

    Mapping m = move(mm);
    remove_from_map(m.map);

    LOG(debug) << "  erased (" << m.map << ") ...";

    // If the first segment we unmap underflows the unmap
    // region, remap the underflow region.
    auto monitored = m.monitored_shared_memory;
    if (m.map.start() < rem.start()) {
      Mapping underflow(m.map.subrange(m.map.start(), rem.start()),
                        m.recorded_map.subrange(m.map.start(), rem.start()),
                        m.emu_file, clone_stat(m.mapped_file_stat),
                        m.local_addr, move(monitored));
      underflow.flags = m.flags;
      add_to_map(underflow);
    }
    // If the last segment we unmap overflows the unmap
    // region, remap the overflow region.
    if (rem.end() < m.map.end()) {
      Mapping overflow(
          m.map.subrange(rem.end(), m.map.end()),
          m.recorded_map.subrange(rem.end(), m.map.end()), m.emu_file,
          clone_stat(m.mapped_file_stat),
          m.local_addr ? m.local_addr + (rem.end() - m.map.start()) : 0,
          m.monitored_shared_memory
              ? m.monitored_shared_memory->subrange(rem.end() - m.map.start(),
                                                    m.map.end() - rem.end())
              : nullptr);
      overflow.flags = m.flags;
      add_to_map(overflow);
    }

    if (m.local_addr) {
      auto addr = m.local_addr + (rem.start() - m.map.start());
      auto size = std::min(rem.size(), m.map.size() - (rem.start() - m.map.start()));
      int ret = munmap(addr, size);
      if (ret < 0) {
        FATAL() << "Can't munmap";
      }
    }
  };
  for_each_in_range(addr, num_bytes, unmapper);
  update_watchpoint_values(addr, addr + num_bytes);
}

void AddressSpace::advise(Task*, remote_ptr<void> addr, ssize_t num_bytes,
                          int advice) {
  LOG(debug) << "madvise(" << addr << ", " << num_bytes << ", " << advice
             << ")";
  num_bytes = ceil_page_size(num_bytes);

  switch (advice) {
    case MADV_DONTFORK:
      add_range(dont_fork, MemoryRange(addr, num_bytes));
      break;
    case MADV_DOFORK:
      remove_range(dont_fork, MemoryRange(addr, num_bytes));
      break;
    case MADV_WIPEONFORK:
      add_range(wipe_on_fork, MemoryRange(addr, num_bytes));
      break;
    case MADV_KEEPONFORK:
      remove_range(wipe_on_fork, MemoryRange(addr, num_bytes));
      break;
    default:
      break;
  }
}

void AddressSpace::did_fork_into(Task* t) {
  // MADV_WIPEONFORK is inherited across fork and cleared on exec.
  // We'll copy it here, then do the `dont_fork` unmappings, and then
  // whatever survives in the new AddressSpace's wipe_on_fork gets wiped.
  t->vm()->wipe_on_fork = wipe_on_fork;

  for (auto& range : dont_fork) {
    // During recording we execute MADV_DONTFORK so the forked child will
    // have had its dontfork areas unmapped by the kernel already
    if (!t->session().is_recording()) {
      AutoRemoteSyscalls remote(t);
      remote.infallible_syscall(syscall_number_for_munmap(remote.arch()),
                                range.start(), range.size());
    }
    t->vm()->unmap(t, range.start(), range.size());
  }

  // Any ranges that were dropped were unmapped (and thus removed from
  // wipe_on_fork), so now we can record anything that's left.
  for (auto& range : t->vm()->wipe_on_fork) {
    if (t->session().is_recording()) {
      // Record that these mappings were wiped.
      RecordTask* rt = static_cast<RecordTask*>(t);
      rt->record_remote(range);
    }
  }
}

static string strip_deleted(const string& s) {
  static const char deleted[] = " (deleted)";
  ssize_t find_deleted = s.size() - (sizeof(deleted) - 1);
  if (s.find(deleted) == size_t(find_deleted)) {
    return s.substr(0, find_deleted);
  }
  return s;
}

enum HandleHeap { TREAT_HEAP_AS_ANONYMOUS, RESPECT_HEAP };

static bool normalized_file_names_equal(const KernelMapping& km1,
                                        const KernelMapping& km2,
                                        HandleHeap handle_heap) {
  if (km1.is_stack() || km2.is_stack()) {
    // The kernel seems to use "[stack:<tid>]" for any mapping area containing
    // thread |tid|'s stack pointer. When the thread exits, the next read of
    // the maps doesn't treat the area as stack at all. We don't want to track
    // thread exits, so if one of the mappings is a stack, skip the name
    // comparison. Device and inode numbers will still be checked.
    return true;
  }
  if (handle_heap == TREAT_HEAP_AS_ANONYMOUS &&
      (km1.is_heap() || km2.is_heap())) {
    // The kernel's heuristics for treating an anonymous mapping as "[heap]"
    // are obscure. Just skip the name check. Device and inode numbers will
    // still be checked.
    return true;
  }
  // We don't track when a file gets deleted, so it's possible for the kernel
  // to have " (deleted)" when we don't.
  return strip_deleted(km1.fsname()) == strip_deleted(km2.fsname());
}

/**
 * Return true iff |left| and |right| are located adjacently in memory
 * with the same metadata, and map adjacent locations of the same
 * underlying (real) device.
 */
static bool is_adjacent_mapping(const KernelMapping& mleft,
                                const KernelMapping& mright,
                                HandleHeap handle_heap,
                                int32_t flags_to_check = 0xFFFFFFFF) {
  if (mleft.end() != mright.start()) {
    return false;
  }
  if (((mleft.flags() ^ mright.flags()) & flags_to_check) ||
      mleft.prot() != mright.prot()) {
    return false;
  }
  if (!normalized_file_names_equal(mleft, mright, handle_heap)) {
    return false;
  }
  if (mleft.device() != mright.device() || mleft.inode() != mright.inode()) {
    return false;
  }
  if (mleft.is_real_device() &&
      mleft.file_offset_bytes() + off64_t(mleft.size()) !=
          mright.file_offset_bytes()) {
    return false;
  }
  return true;
}

/**
 * If |*left_m| and |right_m| are adjacent (see
 * |is_adjacent_mapping()|), write a merged segment descriptor to
 * |*left_m| and return true.  Otherwise return false.
 */
static bool try_merge_adjacent(KernelMapping* left_m,
                               const KernelMapping& right_m) {
  if (is_adjacent_mapping(*left_m, right_m, TREAT_HEAP_AS_ANONYMOUS,
                          KernelMapping::checkable_flags_mask)) {
    *left_m = KernelMapping(left_m->start(), right_m.end(), left_m->fsname(),
                            left_m->device(), left_m->inode(), right_m.prot(),
                            right_m.flags(), left_m->file_offset_bytes());
    return true;
  }
  return false;
}

static dev_t normalized_device_number(const KernelMapping& m) {
  if (m.fsname().c_str()[0] != '/') {
    return m.device();
  }
  // btrfs files can report the wrong device number in /proc/<pid>/maps, so
  // restrict ourselves to checking whether the device number is != 0
  if (m.device() != KernelMapping::NO_DEVICE) {
    return (dev_t)-1;
  }
  return m.device();
}

static void assert_segments_match(Task* t, const KernelMapping& input_m,
                                  const KernelMapping& km) {
  KernelMapping m = input_m;
  string err;
  if (m.start() != km.start()) {
    err = "starts differ";
  } else if (m.end() != km.end()) {
    err = "ends differ";
  } else if (m.prot() != km.prot()) {
    err = "prots differ";
  } else if ((m.flags() ^ km.flags()) & KernelMapping::checkable_flags_mask) {
    err = "flags differ";
  } else if (!normalized_file_names_equal(m, km, TREAT_HEAP_AS_ANONYMOUS) &&
             !(km.is_heap() && m.fsname() == "") &&
             !(m.is_heap() && km.fsname() == "") && !km.is_vdso()) {
    // Due to emulated exec, the kernel may identify any of our anonymous maps
    // as [heap] (or not).
    // Kernels before 3.16 have a bug where any mapping at the original VDSO
    // address is marked [vdso] even if the VDSO was unmapped and replaced by
    // something else, so if the kernel reports [vdso] it may be spurious and
    // we skip this check. See kernel commit
    // a62c34bd2a8a3f159945becd57401e478818d51c.
    err = "filenames differ";
  } else if (normalized_device_number(m) != normalized_device_number(km)) {
    err = "devices_differ";
  } else if (m.inode() != km.inode()) {
    err = "inodes differ";
  }
  if (err.size()) {
    LOG(error) << "cached mmap:";
    t->vm()->dump();
    LOG(error) << "/proc/" << t->tid << "/mmaps:";
    AddressSpace::print_process_maps(t);
    ASSERT(t, false) << "\nCached mapping " << m << " should be " << km << "; "
                     << err;
  }
}

void AddressSpace::ensure_replay_matches_single_recorded_mapping(Task* t, MemoryRange range) {
  // The only case where we eagerly coalesced during recording but not replay should
  // be where we mapped private memory beyond-end-of-file.
  // Don't do an actual coalescing check here; we rely on the caller to tell us
  // the range to coalesce.
  ASSERT(t, range.start() == floor_page_size(range.start()));
  ASSERT(t, range.end() == ceil_page_size(range.end()));

  auto fixer = [this, t, range](const Mapping& mm, const MemoryRange&) {
    if (mm.map == range) {
      // Existing single mapping covers entire range; nothing to do.
      return;
    }
    Mapping mapping = move(mm);

    // These should be null during replay
    ASSERT(t, !mapping.mapped_file_stat);
    // These should not be in use for a beyond-end-of-file mapping
    ASSERT(t, !mapping.local_addr);
    // The mapping should be private
    ASSERT(t, mapping.map.flags() & MAP_PRIVATE);
    ASSERT(t, !mapping.emu_file);
    ASSERT(t, !mapping.monitored_shared_memory);
    // Flagged mappings shouldn't be coalescable ever
    ASSERT(t, !mapping.flags);

    if (!(mapping.map.flags() & MAP_ANONYMOUS)) {
      // Direct-mapped piece. Turn it into an anonymous mapping.
      vector<uint8_t> buffer;
      buffer.resize(mapping.map.size());
      t->read_bytes_helper(mapping.map.start(), buffer.size(), buffer.data());
      {
        AutoRemoteSyscalls remote(t);
        remote.infallible_mmap_syscall(mapping.map.start(), buffer.size(),
            mapping.map.prot(), mapping.map.flags() | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
      }
      t->write_bytes_helper(mapping.map.start(), buffer.size(), buffer.data());

      // We replace the entire mapping even if part of it falls outside the desired range.
      // That's OK, this replacement preserves behaviour, it's simpler, even if a bit
      // less efficient in weird cases.
      mem.erase(mapping.map);
      KernelMapping anonymous_km(mapping.map.start(), mapping.map.end(),
                                 string(), KernelMapping::NO_DEVICE, KernelMapping::NO_INODE,
                                 mapping.map.prot(), mapping.map.flags() | MAP_ANONYMOUS);
      Mapping new_mapping(anonymous_km, mapping.recorded_map);
      mem[new_mapping.map] = new_mapping;
    }
  };
  for_each_in_range(range.start(), range.size(), fixer);

  coalesce_around(t, mem.find(range));
}

KernelMapping AddressSpace::vdso() const {
  DEBUG_ASSERT(!vdso_start_addr.is_null());
  return mapping_of(vdso_start_addr).map;
}

/**
 * Iterate over /proc/maps segments for a task and verify that the
 * task's cached mapping matches the kernel's (given a lenient fuzz
 * factor).
 */
void AddressSpace::verify(Task* t) const {
  ASSERT(t, task_set().end() != task_set().find(t));

  if (thread_group_in_exec(t)) {
    return;
  }

  LOG(debug) << "Verifying address space for task " << t->tid;

  MemoryMap::const_iterator mem_it = mem.begin();
  KernelMapIterator kernel_it(t);
  if (kernel_it.at_end()) {
    LOG(debug) << "Task " << t->tid << " exited unexpectedly, ignoring";
    return;
  }
  while (!kernel_it.at_end() && mem_it != mem.end()) {
    KernelMapping km = kernel_it.current();
    ++kernel_it;
    while (!kernel_it.at_end()) {
      KernelMapping next_km = kernel_it.current();
      if (!try_merge_adjacent(&km, next_km)) {
        break;
      }
      ++kernel_it;
    }

    KernelMapping vm = mem_it->second.map;
    ++mem_it;
    while (mem_it != mem.end() && try_merge_adjacent(&vm, mem_it->second.map)) {
      ++mem_it;
    }

    assert_segments_match(t, vm, km);
  }

  ASSERT(t, kernel_it.at_end() && mem_it == mem.end());
}

// Just a place that rr's AutoSyscall functionality can use as a syscall
// instruction in rr's address space for use before we have exec'd.
extern "C" {
// Mark this as hidden, otherwise we might get the address of the GOT entry,
// which could cause problems.
extern char rr_syscall_addr __attribute__ ((visibility ("hidden")));
}
static void __attribute__((noinline, used)) fake_syscall() {
#ifdef __i386__
  __asm__ __volatile__("rr_syscall_addr: int $0x80\n\t"
                       "nop\n\t"
                       "nop\n\t"
                       "nop\n\t");
#elif defined(__x86_64__)
  __asm__ __volatile__("rr_syscall_addr: syscall\n\t"
                       "nop\n\t"
                       "nop\n\t"
                       "nop\n\t");
#elif defined(__aarch64__)
  __asm__ __volatile__("rr_syscall_addr: svc #0\n\t"
                       "nop\n\t"
                       "nop\n\t"
                       "nop\n\t");
#endif
}

AddressSpace::AddressSpace(Task* t, const string& exe, uint32_t exec_count)
    : exe(exe),
      leader_tid_(t->rec_tid),
      leader_serial(t->tuid().serial()),
      exec_count(exec_count),
      session_(&t->session()),
      monkeypatch_state(t->session().is_recording() ? new Monkeypatcher()
                                                    : nullptr),
      syscallbuf_enabled_(false),
      do_breakpoint_fault_addr_(nullptr),
      stopping_breakpoint_table_(nullptr),
      stopping_breakpoint_table_entry_size_(0),
      first_run_event_(0) {
  // TODO: this is a workaround of
  // https://github.com/rr-debugger/rr/issues/1113 .
  if (session_->done_initial_exec()) {
    populate_address_space(t);
    DEBUG_ASSERT(!vdso_start_addr.is_null());
  } else {
    // Setup traced_syscall_ip_ now because we need to do AutoRemoteSyscalls
    // (for open_mem_fd) before the first exec. We rely on the fact that we
    // haven't execed yet, so the address space layout is the same.
    traced_syscall_ip_ = remote_code_ptr((uintptr_t)&rr_syscall_addr);
  }
}

AddressSpace::AddressSpace(Session* session, const AddressSpace& o,
                           pid_t leader_tid, uint32_t leader_serial,
                           uint32_t exec_count)
    : exe(o.exe),
      leader_tid_(leader_tid),
      leader_serial(leader_serial),
      exec_count(exec_count),
      brk_start(o.brk_start),
      brk_end(o.brk_end),
      mem(o.mem),
      shm_sizes(o.shm_sizes),
      monitored_mem(o.monitored_mem),
      session_(session),
      vdso_start_addr(o.vdso_start_addr),
      monkeypatch_state(o.monkeypatch_state
                            ? new Monkeypatcher(*o.monkeypatch_state)
                            : nullptr),
      traced_syscall_ip_(o.traced_syscall_ip_),
      privileged_traced_syscall_ip_(o.privileged_traced_syscall_ip_),
      syscallbuf_enabled_(o.syscallbuf_enabled_),
      do_breakpoint_fault_addr_(o.do_breakpoint_fault_addr_),
      stopping_breakpoint_table_(o.stopping_breakpoint_table_),
      stopping_breakpoint_table_entry_size_(o.stopping_breakpoint_table_entry_size_),
      saved_auxv_(o.saved_auxv_),
      saved_interpreter_base_(o.saved_interpreter_base_),
      saved_ld_path_(o.saved_ld_path_),
      first_run_event_(0) {
  for (auto& m : mem) {
    // The original address space continues to have exclusive ownership of
    // all local mappings.
    m.second.local_addr = nullptr;
  }

  for (auto& it : o.breakpoints) {
    breakpoints.insert(make_pair(it.first, it.second));
  }
  for (auto& it : o.watchpoints) {
    watchpoints.insert(make_pair(it.first, it.second));
  }
  if (session != o.session()) {
    // Cloning into a new session means we're checkpointing.
    first_run_event_ = o.first_run_event_;
  }
  // cloned tasks will automatically get cloned debug registers and
  // cloned address-space memory, so we don't need to do any more work here.
}

bool AddressSpace::post_vm_clone(Task* t) {
  if (has_mapping(preload_thread_locals_start()) &&
      (mapping_flags_of(preload_thread_locals_start()) &
       AddressSpace::Mapping::IS_THREAD_LOCALS) == 0) {
    // The tracee already has a mapping at this address that doesn't belong to
    // us. Don't touch it.
    return false;
  }

  // Otherwise, the preload_thread_locals mapping is non-existent or ours.
  // Recreate it.
  AutoRemoteSyscalls remote(t);
  t->session().create_shared_mmap(remote, PRELOAD_THREAD_LOCALS_SIZE,
                                  preload_thread_locals_start(),
                                  "preload_thread_locals");
  mapping_flags_of(preload_thread_locals_start()) |=
      AddressSpace::Mapping::IS_THREAD_LOCALS;
  return true;
}

static bool try_split_unaligned_range(MemoryRange& range, size_t bytes,
                                      vector<MemoryRange>& result) {
  if ((range.start().as_int() & (bytes - 1)) || range.size() < bytes) {
    return false;
  }
  result.push_back(MemoryRange(range.start(), bytes));
  range = MemoryRange(range.start() + bytes, range.end());
  return true;
}

static vector<MemoryRange> split_range(const MemoryRange& range) {
  vector<MemoryRange> result;
  MemoryRange r = range;
  while (r.size() > 0) {
    if ((sizeof(void*) < 8 || !try_split_unaligned_range(r, 8, result)) &&
        !try_split_unaligned_range(r, 4, result) &&
        !try_split_unaligned_range(r, 2, result)) {
      bool ret = try_split_unaligned_range(r, 1, result);
      DEBUG_ASSERT(ret);
    }
  }
  return result;
}

static void configure_watch_registers(vector<WatchConfig>& regs,
                                      const MemoryRange& range, WatchType type,
                                      vector<int8_t>* assigned_regs) {
  // Zero-sized WatchConfigs return no ranges here, so are ignored.
  auto split_ranges = split_range(range);

  if (type == WATCH_WRITE && range.size() > 1) {
    // We can suppress spurious write-watchpoint triggerings by checking
    // whether memory values have changed. So we can sometimes conserve
    // debug registers by upgrading an unaligned range to an aligned range
    // of a larger size.
    uintptr_t align;
    if (range.size() <= 2) {
      align = 2;
    } else if (range.size() <= 4 || sizeof(void*) <= 4) {
      align = 4;
    } else {
      align = 8;
    }
    remote_ptr<void> aligned_start(range.start().as_int() & ~(align - 1));
    remote_ptr<void> aligned_end((range.end().as_int() + (align - 1)) &
                                 ~(align - 1));
    auto split = split_range(MemoryRange(aligned_start, aligned_end));
    // If the aligned range doesn't reduce register usage, use the original
    // split to avoid spurious triggerings
    if (split.size() < split_ranges.size()) {
      split_ranges = split;
    }
  }

  for (auto& r : split_ranges) {
    if (assigned_regs) {
      assigned_regs->push_back(regs.size());
    }
    regs.push_back(WatchConfig(r.start(), r.size(), type));
  }
}

vector<WatchConfig> AddressSpace::get_watch_configs(
    WillSetTaskState will_set_task_state) {
  vector<WatchConfig> result;
  for (auto& kv : watchpoints) {
    vector<int8_t>* assigned_regs = nullptr;
    if (will_set_task_state == SETTING_TASK_STATE) {
      kv.second.debug_regs_for_exec_read.clear();
      assigned_regs = &kv.second.debug_regs_for_exec_read;
    }
    const MemoryRange& r = kv.first;
    int watching = kv.second.watched_bits();
    if (EXEC_BIT & watching) {
      configure_watch_registers(result, r, WATCH_EXEC, assigned_regs);
    }
    if (READ_BIT & watching) {
      configure_watch_registers(result, r, WATCH_READWRITE, assigned_regs);
    } else if (WRITE_BIT & watching) {
      configure_watch_registers(result, r, WATCH_WRITE, nullptr);
    }
  }
  return result;
}

vector<WatchConfig> AddressSpace::get_watchpoints_internal(
    WatchpointFilter filter) {
  vector<WatchConfig> result;
  for (auto& kv : watchpoints) {
    if (filter == CHANGED_WATCHPOINTS) {
      if (!kv.second.changed) {
        continue;
      }
      kv.second.changed = false;
    }
    const MemoryRange& r = kv.first;
    int watching = kv.second.watched_bits();
    if (EXEC_BIT & watching) {
      result.push_back(WatchConfig(r.start(), r.size(), WATCH_EXEC));
    }
    if (READ_BIT & watching) {
      result.push_back(WatchConfig(r.start(), r.size(), WATCH_READWRITE));
    } else if (WRITE_BIT & watching) {
      result.push_back(WatchConfig(r.start(), r.size(), WATCH_WRITE));
    }
  }
  return result;
}

vector<WatchConfig> AddressSpace::consume_watchpoint_changes() {
  return get_watchpoints_internal(CHANGED_WATCHPOINTS);
}

vector<WatchConfig> AddressSpace::all_watchpoints() {
  return get_watchpoints_internal(ALL_WATCHPOINTS);
}

bool AddressSpace::has_any_watchpoint_changes() {
  for (auto& kv : watchpoints) {
    if (kv.second.changed) {
      return true;
    }
  }
  return false;
}

bool AddressSpace::has_exec_watchpoint_fired(remote_code_ptr addr) {
  for (auto& kv : watchpoints) {
    if (kv.second.changed && kv.second.exec_count > 0 &&
        kv.first.start() == addr.to_data_ptr<void>()) {
      return true;
    }
  }
  return false;
}

bool AddressSpace::allocate_watchpoints() {
  Task::DebugRegs regs = get_watch_configs(SETTING_TASK_STATE);

  if (regs.size() <= 0x7f) {
    bool ok = true;
    for (auto t : task_set()) {
      if (!t->set_debug_regs(regs)) {
        ok = false;
      }
    }
    if (ok) {
      return true;
    }
  }

  regs.clear();
  for (auto t2 : task_set()) {
    t2->set_debug_regs(regs);
  }
  for (auto kv : watchpoints) {
    kv.second.debug_regs_for_exec_read.clear();
  }
  return false;
}

static inline void assert_coalesceable(Task* t,
                                       const AddressSpace::Mapping& lower,
                                       const AddressSpace::Mapping& higher) {
  ASSERT(t, lower.emu_file == higher.emu_file);
  ASSERT(t, lower.flags == higher.flags);
  ASSERT(t,
         (lower.local_addr == 0 && higher.local_addr == 0) ||
             lower.local_addr + lower.map.size() == higher.local_addr);
  ASSERT(t, !lower.monitored_shared_memory && !higher.monitored_shared_memory);
}

static bool is_coalescable(const AddressSpace::Mapping& mleft,
                           const AddressSpace::Mapping& mright) {
  if (!is_adjacent_mapping(mleft.map, mright.map, RESPECT_HEAP) ||
      !is_adjacent_mapping(mleft.recorded_map, mright.recorded_map,
                           RESPECT_HEAP)) {
    return false;
  }
  return mleft.flags == mright.flags;
}

void AddressSpace::coalesce_around(Task* t, MemoryMap::iterator it) {
  auto first_kv = it;
  while (mem.begin() != first_kv) {
    auto next = first_kv;
    --first_kv;
    if (!is_coalescable(first_kv->second, next->second)) {
      first_kv = next;
      break;
    }
    assert_coalesceable(t, first_kv->second, next->second);
  }
  auto last_kv = it;
  while (true) {
    auto prev = last_kv;
    ++last_kv;
    if (mem.end() == last_kv ||
        !is_coalescable(prev->second, last_kv->second)) {
      last_kv = prev;
      break;
    }
    assert_coalesceable(t, prev->second, last_kv->second);
  }
  ASSERT(t, last_kv != mem.end());
  if (first_kv == last_kv) {
    LOG(debug) << "  no mappings to coalesce";
    return;
  }

  Mapping new_m(first_kv->second.map.extend(last_kv->first.end()),
                first_kv->second.recorded_map.extend(last_kv->first.end()),
                first_kv->second.emu_file,
                clone_stat(first_kv->second.mapped_file_stat),
                first_kv->second.local_addr);
  new_m.flags = first_kv->second.flags;
  LOG(debug) << "  coalescing " << new_m.map;

  // monitored-memory currently isn't coalescable so we don't need to
  // adjust monitored_mem
  mem.erase(first_kv, ++last_kv);

  auto ins = mem.insert(MemoryMap::value_type(new_m.map, new_m));
  DEBUG_ASSERT(ins.second); // key didn't already exist
}

void AddressSpace::destroy_breakpoint(BreakpointMap::const_iterator it) {
  if (task_set().empty()) {
    return;
  }
  Task* t = *task_set().begin();
  auto ptr = it->first.to_data_ptr<uint8_t>();
  auto data = it->second.overwritten_data;
  if (bkpt_instruction_length(arch()) == 1) {
    LOG(debug) << "Writing back " << HEX(data[0]) << " at " << ptr;
  } else {
    LOG(debug) << "Writing back " << bkpt_instruction_length(arch()) << " bytes at " << ptr;
  }
  t->write_bytes_helper(ptr, bkpt_instruction_length(arch()),
    data, nullptr, Task::IS_BREAKPOINT_RELATED);
  breakpoints.erase(it);
}

void AddressSpace::maybe_update_breakpoints(Task* t, remote_ptr<uint8_t> addr,
                                            size_t len) {
  for (auto& it : breakpoints) {
    remote_ptr<uint8_t> bp_addr = it.first.to_data_ptr<uint8_t>();
    if (addr <= bp_addr && bp_addr < addr + len - 1) {
      // This breakpoint was overwritten. Note the new data and reset the
      // breakpoint.
      bool ok = true;
      t->read_bytes_helper(bp_addr, bkpt_instruction_length(arch()),
        &it.second.overwritten_data, &ok);
      ASSERT(t, ok);
      t->write_bytes_helper(bp_addr, bkpt_instruction_length(arch()),
        breakpoint_insn(arch()));
    }
  }
}

void AddressSpace::for_each_in_range(
    remote_ptr<void> addr, ssize_t num_bytes,
    function<void(const Mapping& m, const MemoryRange& rem)> f, int how) {
  remote_ptr<void> region_start = floor_page_size(addr);
  remote_ptr<void> last_unmapped_end = region_start;
  remote_ptr<void> region_end = ceil_page_size(addr + num_bytes);
  while (last_unmapped_end < region_end) {
    // Invariant: |rem| is always exactly the region of
    // memory remaining to be examined for pages to be
    // unmapped.
    MemoryRange rem(last_unmapped_end, region_end);

    // The next page to iterate may not be contiguous with
    // the last one seen.
    auto it = mem.lower_bound(rem);
    if (mem.end() == it) {
      LOG(debug) << "  not found, done.";
      return;
    }

    // Don't make a reference here. |f| is allowed to erase Mappings.
    MemoryRange range = it->first;
    if (rem.end() <= range.start()) {
      LOG(debug) << "  mapping at " << range.start() << " out of range, done.";
      return;
    }
    if (ITERATE_CONTIGUOUS == how &&
        !(range.start() < region_start || rem.start() == range.start())) {
      LOG(debug) << "  discontiguous mapping at " << range.start() << ", done.";
      return;
    }

    f(it->second, rem);

    // Maintain the loop invariant.
    last_unmapped_end = range.end();
  }
}

void AddressSpace::map_and_coalesce(
    Task* t, const KernelMapping& m, const KernelMapping& recorded_map,
    EmuFile::shr_ptr emu_file, unique_ptr<struct stat> mapped_file_stat,
    void* local_addr, shared_ptr<MonitoredSharedMemory>&& monitored) {
  LOG(debug) << "  mapping " << m;

  if (monitored) {
    monitored_mem.insert(m.start());
  }
  auto ins = mem.insert(MemoryMap::value_type(
      m, Mapping(m, recorded_map, emu_file, move(mapped_file_stat), local_addr,
                 move(monitored))));
  coalesce_around(t, ins.first);

  update_watchpoint_values(m.start(), m.end());
}

static bool could_be_stack(const KernelMapping& km) {
  // On 4.1.6-200.fc22.x86_64 we observe that during exec of the rr_exec_stub
  // during replay, when the process switches from 32-bit to 64-bit, the 64-bit
  // registers seem truncated to 32 bits during the initial PTRACE_GETREGS so
  // our sp looks wrong and /proc/<pid>/maps doesn't identify the region as
  // stack.
  // On stub execs there should only be one read-writable memory area anyway.
  return km.prot() == (PROT_READ | PROT_WRITE) && km.fsname() == "" &&
         km.device() == KernelMapping::NO_DEVICE &&
         km.inode() == KernelMapping::NO_INODE;
}

static dev_t check_device(const KernelMapping& km) {
  if (km.fsname().c_str()[0] != '/') {
    return km.device();
  }
  // btrfs files can return the wrong device number in /proc/<pid>/maps
  struct stat st;
  int ret = stat(km.fsname().c_str(), &st);
  if (ret < 0) {
    return km.device();
  }
  return st.st_dev;
}

void AddressSpace::populate_address_space(Task* t) {
  bool found_proper_stack = false;
  for (KernelMapIterator it(t); !it.at_end(); ++it) {
    auto& km = it.current();
    if (km.is_stack()) {
      found_proper_stack = true;
    }
  }

  // If we're being recorded by rr, we'll see the outer rr's rr_page and
  // preload_thread_locals. In post_exec() we'll remap those with our
  // own mappings. That's OK because a) the rr_page contents are the same
  // anyway and immutable and b) the preload_thread_locals page is only
  // used by the preload library, and the preload library only knows about
  // the inner rr. I.e. as far as the outer rr is concerned, the tracee is
  // not doing syscall buffering.

  int found_stacks = 0;
  for (KernelMapIterator it(t); !it.at_end(); ++it) {
    auto& km = it.current();
    int flags = km.flags();
    remote_ptr<void> start = km.start();
    bool is_stack = found_proper_stack ? km.is_stack() : could_be_stack(km);
    if (is_stack) {
      ++found_stacks;
      flags |= MAP_GROWSDOWN;
      if (uses_invisible_guard_page()) {
        // MAP_GROWSDOWN segments really occupy one additional page before
        // the start address shown by /proc/<pid>/maps --- unless that page
        // is already occupied by another mapping.
        if (!has_mapping(start - page_size())) {
          start -= page_size();
        }
      }
    }

    map(t, start, km.end() - start, km.prot(), flags, km.file_offset_bytes(),
        km.fsname(), check_device(km), km.inode(), nullptr);
  }
  ASSERT(t, found_stacks == 1);
}

static int random_addr_bits(SupportedArch arch) {
  switch (arch) {
    default:
      DEBUG_ASSERT(0 && "Unknown architecture");
      RR_FALLTHROUGH;
    case x86:
      return 32;
    // Current x86-64 systems have only 48 bits of virtual address space,
    // and only the bottom half is usable by user space
    case x86_64:
      return 47;
    // Aarch64 has 48 bit address space, with user and kernel each getting
    // their own 48 bits worth of address space at opposite end of the full
    // 64-bit address space.
    case aarch64:
      return 48;
  }
}

static MemoryRange adjust_range_for_stack_growth(const KernelMapping& km) {
  remote_ptr<void> start = km.start();
  if (km.flags() & MAP_GROWSDOWN) {
    start = min(start, km.end() - AddressSpace::chaos_mode_min_stack_size());
  }
  return MemoryRange(start, km.end());
}

// Choose a 4TB range to exclude from random mappings. This makes room for
// advanced trace analysis tools that require a large address range in tracees
// that is never mapped.
static MemoryRange choose_global_exclusion_range() {
  if (sizeof(uintptr_t) < 8) {
    return MemoryRange(nullptr, 0);
  }

  const uint64_t range_size = uint64_t(4)*1024*1024*1024*1024;
  int bits = random_addr_bits(x86_64);
  uint64_t r = ((uint64_t)(uint32_t)random() << 32) | (uint32_t)random();
  uint64_t r_addr = r & ((uint64_t(1) << bits) - 1);
  r_addr = min(r_addr, (uint64_t(1) << bits) - range_size);
  remote_ptr<void> addr = floor_page_size(remote_ptr<void>(r_addr));
  return MemoryRange(addr, (uintptr_t)range_size);
}

remote_ptr<void> AddressSpace::chaos_mode_find_free_memory(RecordTask* t,
                                                           size_t len) {
  static MemoryRange global_exclusion_range = choose_global_exclusion_range();

  int bits = random_addr_bits(t->arch());
  uint64_t addr_space_limit = uint64_t(1) << bits;
  while (true) {
    remote_ptr<void> addr;
    // Half the time, try to allocate at a completely random address. The other
    // half of the time, we'll try to allocate immediately before or after a
    // randomly chosen existing mapping.
    if (random() % 2) {
      // Some of these addresses will not be mappable. That's fine, the
      // kernel will fall back to a valid address if the hint is not valid.
      uint64_t r = ((uint64_t)(uint32_t)random() << 32) | (uint32_t)random();
      addr = floor_page_size(remote_ptr<void>(r & (addr_space_limit - 1)));
    } else {
      ASSERT(t, !mem.empty());
      int map_index = random() % mem.size();
      int map_count = 0;
      for (const auto& m : maps()) {
        if (map_count == map_index) {
          addr = m.map.start();
          break;
        }
        ++map_count;
      }
    }

    // If there's a collision (which there always will be in the second case
    // above), either move the mapping forwards or backwards in memory until it
    // fits. Choose the direction randomly.
    int direction = (random() % 2) ? 1 : -1;
    while (true) {
      Maps m = maps_starting_at(addr);
      if (m.begin() == m.end()) {
        break;
      }
      MemoryRange range = adjust_range_for_stack_growth(m.begin()->map);
      if (range.start() >= addr + len) {
        // No overlap with an existing mapping; we're good!
        break;
      }
      if (direction == -1) {
        addr = range.start() - len;
      } else {
        addr = range.end();
      }
    }

    if (uint64_t(addr.as_int()) >= addr_space_limit ||
        uint64_t(addr.as_int()) + ceil_page_size(len) >= addr_space_limit) {
      // We fell off one end of the address space. Try everything again.
      continue;
    }
    MemoryRange r(addr, ceil_page_size(len));
    if (r.intersects(global_exclusion_range)) {
      continue;
    }
    if (t->session().asan_active() && sizeof(size_t) == 8) {
      LOG(debug) << "Checking ASAN shadow";
      MemoryRange asan_shadow(remote_ptr<void>((uintptr_t)0x00007fff7000LL),
                              remote_ptr<void>((uintptr_t)0x10007fff8000LL));
      MemoryRange asan_allocator_reserved(remote_ptr<void>((uintptr_t)0x600000000000LL),
                                          remote_ptr<void>((uintptr_t)0x640000000000LL));
      if (r.intersects(asan_shadow) || r.intersects(asan_allocator_reserved)) {
        continue;
      }
    }

    return addr;
  }
}

remote_ptr<void> AddressSpace::find_free_memory(size_t required_space,
                                                remote_ptr<void> after) {
  auto maps = maps_starting_at(after);
  auto current = maps.begin();
  while (current != maps.end()) {
    auto next = current;
    ++next;
    if (next == maps.end()) {
      if (current->map.end() + required_space >= current->map.end()) {
        break;
      }
    } else {
      if (current->map.end() + required_space <= next->map.start()) {
        break;
      }
    }
    current = next;
  }
  return current->map.end();
}

void AddressSpace::add_stap_semaphore_range(Task* task, MemoryRange range) {
  ASSERT(task, range.start() != range.end())
    << "Unexpected zero-length SystemTap semaphore range: " << range;
  ASSERT(task, (range.size() & 1) == 0)
    << "Invalid SystemTap semaphore range at "
    << range
    << ": size is not a multiple of the size of a STap semaphore!";

  auto ptr = range.start().cast<uint16_t>(),
       end = range.end().cast<uint16_t>();
  for (; ptr < end; ++ptr) {
    stap_semaphores.insert(ptr);
  }
}

void AddressSpace::remove_stap_semaphore_range(Task* task, MemoryRange range) {
  ASSERT(task, range.start() != range.end())
    << "Unexpected zero-length SystemTap semaphore range: " << range;
  ASSERT(task, (range.size() & 1) == 0)
    << "Invalid SystemTap semaphore range at "
    << range
    << ": size is not a multiple of the size of a STap semaphore!";

  auto ptr = range.start().cast<uint16_t>(),
       end = range.end().cast<uint16_t>();
  for (; ptr < end; ++ptr) {
    stap_semaphores.erase(ptr);
  }
}

bool AddressSpace::is_stap_semaphore(remote_ptr<uint16_t> addr) {
  return stap_semaphores.find(addr) != stap_semaphores.end();
}

void AddressSpace::fd_tables_changed() {
  if (!session()->is_recording()) {
    // All modifications are recorded during record
    return;
  }
  if (!syscallbuf_enabled()) {
    return;
  }
  DEBUG_ASSERT(task_set().size() != 0);
  uint8_t fdt_uniform = true;
  RecordTask* rt = nullptr;
  // Find a suitable task
  for (auto* t : task_set()) {
    if (!t->is_dying()) {
      rt = static_cast<RecordTask*>(t);
    }
  }
  if (!rt) {
    return;
  }
  auto fdt = rt->fd_table();
  for (auto* t : task_set()) {
    if (t->fd_table() != fdt) {
      fdt_uniform = false;
    }
  }
  auto addr = REMOTE_PTR_FIELD(rt->preload_globals, fdt_uniform);
  bool ok = true;
  if (rt->read_mem(addr, &ok) != fdt_uniform) {
    if (!ok) {
      return;
    }
    rt->write_mem(addr, fdt_uniform);
    rt->record_local(addr, sizeof(fdt_uniform), &fdt_uniform);
  }
}

} // namespace rr
