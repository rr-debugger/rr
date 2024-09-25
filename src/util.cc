/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <elf.h>
#ifdef EXECINFO_BACKTRACE
#include <execinfo.h>
#endif
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/capability.h>
#include <linux/magic.h>
#include <linux/prctl.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <algorithm>
#include <fstream>
#include <string>
#include <numeric>
#include <random>
#include <sstream>

#include "preload/preload_interface.h"

#include "AddressSpace.h"
#include "AutoRemoteSyscalls.h"
#include "Flags.h"
#include "PerfCounters.h"
#include "ReplaySession.h"
#include "RecordTask.h"
#include "ReplayTask.h"
#include "ScopedFd.h"
#include "TraceStream.h"
#include "WaitManager.h"
#include "core.h"
#include "kernel_abi.h"
#include "kernel_metadata.h"
#include "log.h"
#include "seccomp-bpf.h"

void good_random(uint8_t* out, size_t out_len);

using namespace std;

namespace rr {

template <typename Arch> static remote_ptr<typename Arch::unsigned_word> env_ptr(Task* t) {
  auto stack_ptr = t->regs().sp().cast<typename Arch::unsigned_word>();

  auto argc = t->read_mem(stack_ptr);
  stack_ptr += argc + 1;

  // Check final NULL in argv
  auto null_ptr = t->read_mem(stack_ptr);
  ASSERT(t, null_ptr == 0);
  stack_ptr++;
  return stack_ptr;
}

template <typename Arch> remote_ptr<typename Arch::unsigned_word> auxv_ptr(Task* t) {
  auto stack_ptr = env_ptr<Arch>(t);

  // Should now point to envp
  while (0 != t->read_mem(stack_ptr)) {
    stack_ptr++;
  }
  stack_ptr++;
  // should now point to ELF Auxiliary Table
  return stack_ptr;
}

template <typename Arch>
static vector<uint8_t> read_auxv_arch(Task* t, remote_ptr<typename Arch::unsigned_word> stack_ptr) {
  vector<uint8_t> result;
  while (true) {
    auto pair_vec = t->read_mem(stack_ptr, 2);
    stack_ptr += 2;
    typename Arch::unsigned_word pair[2] = { pair_vec[0], pair_vec[1] };
    result.resize(result.size() + sizeof(pair));
    memcpy(result.data() + result.size() - sizeof(pair), pair, sizeof(pair));
    if (pair[0] == 0) {
      break;
    }
  }
  return result;
}

template <typename Arch> static vector<uint8_t> read_auxv_arch(Task* t) {
  auto stack_ptr = auxv_ptr<Arch>(t);
  return read_auxv_arch<Arch>(t, stack_ptr);
}

vector<uint8_t> read_auxv(Task* t) {
  RR_ARCH_FUNCTION(read_auxv_arch, t->arch(), t);
}

remote_ptr<void> read_interpreter_base(std::vector<uint8_t> auxv) {
  if (auxv.size() == 0 || (auxv.size() % sizeof(uint64_t) != 0)) {
    // Corrupted or missing auxv
    return nullptr;
  }
  remote_ptr<void> interpreter_base = nullptr;
  for (size_t i = 0; i < (auxv.size() / sizeof(uint64_t)) - 1; i += 2) {
    uint64_t* entry = ((uint64_t*)auxv.data())+i;
    uint64_t kind = entry[0];
    uint64_t value = entry[1];
    if (kind == AT_BASE) {
      interpreter_base = value;
      break;
    }
  }
  return interpreter_base;
}

std::string read_ld_path(Task* t, remote_ptr<void> interpreter_base) {
  if (!interpreter_base) {
    return {};
  }
  // Find first executable mapping after the interpreter_base and use its fsname().
  // Non-executable maps may not have a file name.
  remote_ptr<void> addr = interpreter_base;
  while (true) {
    if (!t->vm()->has_mapping(addr)) {
      return {};
    }
    const KernelMapping& map = t->vm()->mapping_of(addr).map;
    if (map.prot() & PROT_EXEC) {
      return map.fsname();
    }
    addr = map.end();
  }
}

template <typename Arch> void patch_auxv_vdso_arch(RecordTask* t, uintptr_t search, uintptr_t new_entry_native) {
  auto stack_ptr = auxv_ptr<Arch>(t);
  std::vector<uint8_t> v = read_auxv_arch<Arch>(t, stack_ptr);
  size_t wsize = sizeof(typename Arch::unsigned_word);
  for (int i = 0; (i + 1)*wsize*2 <= v.size(); ++i) {
    if (*((typename Arch::unsigned_word*)(v.data() + i*2*wsize)) == search) {
      auto entry_ptr = stack_ptr + i*2 + 1;
      typename Arch::unsigned_word new_entry = new_entry_native;
      t->write_mem(entry_ptr, new_entry);
      t->record_local(entry_ptr, &new_entry);
      return;
    }
  }
  return;
}

void patch_auxv_vdso(RecordTask* t, uintptr_t search, uintptr_t new_entry) {
  RR_ARCH_FUNCTION(patch_auxv_vdso_arch, t->arch(), t, search, new_entry);
}

template <typename Arch> static vector<string> read_env_arch(Task* t) {
  auto stack_ptr = env_ptr<Arch>(t);

  // Should now point to envp
  vector<string> result;
  while (true) {
    auto p = t->read_mem(stack_ptr);
    stack_ptr++;
    if (!p) {
      break;
    }
    result.push_back(t->read_c_str(remote_ptr<char>(p)));
  }
  return result;
}

vector<string> read_env(Task* t) {
  RR_ARCH_FUNCTION(read_env_arch, t->arch(), t);
}

// FIXME this function assumes that there's only one address space.
// Should instead only look at the address space of the task in
// question.
static bool is_start_of_scratch_region(Task* t, remote_ptr<void> start_addr) {
  for (auto& kv : t->session().tasks()) {
    Task* c = kv.second;
    if (start_addr == c->scratch_ptr) {
      return true;
    }
  }
  return false;
}

bool probably_not_interactive(int fd) {
  if (Flags::get().non_interactive) {
    return true;
  }
  /* Eminently tunable heuristic, but this is guaranteed to be
   * true during rr unit tests, where we care most about this
   * check (to a first degree).  A failing test shouldn't
   * hang. */
  return !isatty(fd);
}

int clone_flags_to_task_flags(int flags_arg) {
  int flags = CLONE_SHARE_NOTHING;
  // See Task.h for description of the flags.
  flags |= (CLONE_CHILD_CLEARTID & flags_arg) ? CLONE_CLEARTID : 0;
  flags |= (CLONE_SETTLS & flags_arg) ? CLONE_SET_TLS : 0;
  flags |= (CLONE_SIGHAND & flags_arg) ? CLONE_SHARE_SIGHANDLERS : 0;
  flags |= (CLONE_THREAD & flags_arg) ? CLONE_SHARE_THREAD_GROUP : 0;
  flags |= (CLONE_VM & flags_arg) ? CLONE_SHARE_VM : 0;
  flags |= (CLONE_FILES & flags_arg) ? CLONE_SHARE_FILES : 0;
  return flags;
}

size_t page_size() {
  /* This sometimes appears in profiles */
  static size_t size = sysconf(_SC_PAGE_SIZE);
  return size;
}

size_t ceil_page_size(size_t sz) {
  size_t page_mask = ~(page_size() - 1);
  return (sz + page_size() - 1) & page_mask;
}

size_t floor_page_size(size_t sz) {
  size_t page_mask = ~(page_size() - 1);
  return sz & page_mask;
}

remote_ptr<void> ceil_page_size(remote_ptr<void> addr) {
  return remote_ptr<void>(ceil_page_size(addr.as_int()));
}

remote_ptr<void> floor_page_size(remote_ptr<void> addr) {
  return remote_ptr<void>(floor_page_size(addr.as_int()));
}

/**
 * Dump |buf_len| words in |buf| to |out|, starting with a line
 * containing |label|.  See |dump_binary_data()| for a description of
 * the remaining parameters.
 */
static void dump_binary_chunk(FILE* out, const char* label, const uint32_t* buf,
                              size_t buf_len, remote_ptr<void> start_addr) {
  int i;

  fprintf(out, "%s\n", label);
  for (i = 0; i < ssize_t(buf_len); i += 1) {
    uint32_t word = buf[i];
    fprintf(out, "0x%08x | [%p]\n", word,
            (void*)(start_addr.as_int() + i * sizeof(*buf)));
  }
}

void dump_binary_data(const char* filename, const char* label,
                      const uint32_t* buf, size_t buf_len,
                      remote_ptr<void> start_addr) {
  FILE* out = fopen64(filename, "w");
  if (!out) {
    return;
  }
  dump_binary_chunk(out, label, buf, buf_len, start_addr);
  fclose(out);
}

string format_dump_filename(Task* t, FrameTime global_time, const char* tag) {
  stringstream s;
  s << t->trace_dir() << "/" << global_time << "_" << t->rec_tid << "_"
    << tag;
  return s.str();
}

bool should_dump_memory(const Event& event, FrameTime time) {
  const Flags* flags = &Flags::get();

  return flags->dump_on == Flags::DUMP_ON_ALL ||
         (event.is_syscall_event() &&
          event.Syscall().number == flags->dump_on) ||
         (event.is_signal_event() &&
          event.Signal().siginfo.si_signo == -flags->dump_on) ||
         (flags->dump_on == Flags::DUMP_ON_RDTSC &&
          event.type() == EV_INSTRUCTION_TRAP) ||
         flags->dump_at == time;
}

void dump_process_memory(Task* t, FrameTime global_time, const char* tag) {
  string filename = format_dump_filename(t, global_time, tag);
  FILE* dump_file = fopen64(filename.c_str(), "w");

  const AddressSpace& as = *(t->vm());
  for (const auto& m : as.maps()) {
    vector<uint8_t> mem;
    mem.resize(m.map.size());

    ssize_t mem_len =
        t->read_bytes_fallible(m.map.start(), m.map.size(), mem.data());
    mem_len = max(ssize_t(0), mem_len);

    if (!is_start_of_scratch_region(t, m.map.start())) {
      dump_binary_chunk(dump_file, m.map.str().c_str(),
                        (const uint32_t*)mem.data(), mem_len / sizeof(uint32_t),
                        m.map.start());
    }
  }
  fclose(dump_file);
}

void write_pt_data(Task* t, FrameTime global_time, const vector<vector<uint8_t>>& data) {
  string filename = format_dump_filename(t, global_time, "pt");
  ScopedFd dump_file(filename.c_str(), O_WRONLY | O_TRUNC | O_CREAT, 0700);
  ASSERT(t, dump_file.is_open()) << "Can't write to file " << filename;
  for (const auto& d : data) {
    write_all(dump_file, d.data(), d.size());
  }
}

vector<uint8_t> read_pt_data(Task* t, FrameTime global_time) {
  string filename = format_dump_filename(t, global_time, "pt");
  FILE* dump_file = fopen64(filename.c_str(), "r");
  vector<uint8_t> result;
  if (!dump_file) {
    return result;
  }

  while (true) {
    char buf[1024*1024];
    size_t bytes_read = fread(buf, 1, sizeof(buf), dump_file);
    if (bytes_read) {
      size_t current_size = result.size();
      result.resize(current_size + bytes_read);
      memcpy(result.data() + current_size, buf, bytes_read);
    }
    if (bytes_read < sizeof(buf)) {
      break;
    }
  }
  fclose(dump_file);
  return result;
}

static void notify_checksum_error(ReplayTask* t, FrameTime global_time,
                                  unsigned checksum, unsigned rec_checksum,
                                  const string& raw_map_line) {
  dump_process_memory(t, global_time, "checksum_error");

  /* TODO: if the right recorder memory dump is present,
   * automatically compare them, taking the oddball
   * not-mapped-during-replay region(s) into account.  And if
   * not present, tell the user how to make one in a future
   * run. */
  string cur_dump = format_dump_filename(t, global_time, "checksum_error");
  string rec_dump = format_dump_filename(t, global_time, "rec");

  const Event& ev = t->current_trace_frame().event();
  ASSERT(t, checksum == rec_checksum)
      << "Divergence in contents of memory segment after '" << ev << "':\n"
                                                                     "\n"
      << raw_map_line << "    (recorded checksum:" << HEX(rec_checksum)
      << "; replaying checksum:" << HEX(checksum) << ")\n"
                                                     "\n"
      << "Dumped current memory contents to " << cur_dump
      << ". If you've created a memory dump for\n"
      << "the '" << ev << "' event (line " << t->trace_time()
      << ") during recording by using, for example with\n"
      << "the args\n"
         "\n"
      << "$ rr --dump-at=" << t->trace_time() << " record ...\n"
                                                 "\n"
      << "then you can use the following to determine which memory cells "
         "differ:\n"
         "\n"
      << "$ diff -u " << rec_dump << " " << cur_dump << " > mem-diverge.diff\n";
}

static bool checksum_segment_filter(const AddressSpace::Mapping& m) {
  struct stat st;
  int may_diverge;

  if (m.map.fsname() == "[vsyscall]") {
    // This can't be read/checksummed.
    return false;
  }
  if (stat(m.map.fsname().c_str(), &st)) {
    /* If there's no persistent resource backing this
     * mapping, we should expect it to change. */
    LOG(debug) << "CHECKSUMMING unlinked '" << m.map.fsname() << "'";
    return true;
  }
  /* If we're pretty sure the backing resource is effectively
   * immutable, skip checksumming, it's a waste of time.  Except
   * if the mapping is mutable, for example the rw data segment
   * of a system library, then it's interesting. */
  static const char mmap_clone[] = "mmap_clone_";
  may_diverge =
      m.map.fsname().substr(0, array_length(mmap_clone) - 1) != mmap_clone &&
      (should_copy_mmap_region(m.map, m.map.fsname(), st) || (PROT_WRITE & m.map.prot()));
  LOG(debug) << (may_diverge ? "CHECKSUMMING" : "  skipping") << " '"
             << m.map.fsname() << "'";
  return may_diverge;
}

static uint32_t compute_checksum(void* data, size_t len) {
  uint32_t checksum = len;
  size_t words = len / sizeof(uint32_t);
  uint32_t* buf = static_cast<uint32_t*>(data);
  for (size_t i = 0; i < words; ++i) {
    checksum = (checksum << 4) + checksum + buf[i];
  }
  return checksum;
}

static const uint32_t ignored_checksum = 0x98765432;
static const uint32_t sigbus_checksum = 0x23456789;

bool should_checksum(const Event& event, FrameTime time) {
  FrameTime checksum = Flags::get().checksum;
  if (Flags::CHECKSUM_NONE == checksum) {
    return false;
  }

  if (event.type() == EV_EXIT) {
    // Task is dead, or at least detached, and we can't read its memory safely.
    return false;
  }
  if (event.has_ticks_slop()) {
    // We may not be at the same point during recording and replay, so don't
    // compute checksums.
    return false;
  }

  if (Flags::CHECKSUM_ALL == checksum) {
    // Don't checksum at syscall entry because we sometimes mutate syscall parameters there
    // and that will cause false divergence
    return EV_SYSCALL != event.type() || ENTERING_SYSCALL != event.Syscall().state;
  }
  if (Flags::CHECKSUM_SYSCALL == checksum) {
    return EV_SYSCALL == event.type() && EXITING_SYSCALL == event.Syscall().state;
  }
  /* |checksum| is a global time point. */
  return checksum <= time;
}

static void normalize_syscallbuf(Task* t, vector<uint8_t>& mem) {
  /* The syscallbuf consists of a region that's written
   * deterministically wrt the trace events, and a
   * region that's written nondeterministically in the
   * same way as trace scratch buffers.  The
   * deterministic region comprises committed syscallbuf
   * records, and possibly the one pending record
   * metadata.  The nondeterministic region starts at
   * the "extra data" for the possibly one pending
   * record.
   *
   * The deterministic region excludes the notify_on_syscall_hook_exit
   * flag. This flag is written by is_safe_to_deliver_signal and
   * that write can occur at a different event to where ReplaySession
   * eventually sets it.
   *
   * So here, we set things up so that we only checksum
   * the deterministic region. */
  struct syscallbuf_hdr hdr;
  size_t hdr_size = t->session().syscallbuf_hdr_size();
  ASSERT(t, mem.size() >= hdr_size);
  memcpy(&hdr, mem.data(), hdr_size);
  hdr.notify_on_syscall_hook_exit = 0;
  memcpy(mem.data(), &hdr, hdr_size);
  mem.resize(hdr_size + hdr.num_rec_bytes + sizeof(struct syscallbuf_record));
}

void checksum_process_memory(RecordTask* t, FrameTime global_time) {
  string filename = format_dump_filename(t, global_time, "mem_checksums");
  FILE* checksums_file = fopen64(filename.c_str(), "w");
  if (!checksums_file) {
    FATAL() << "Failed to open checksum file " << filename;
  }

  AddressSpace& as = *t->vm();
  for (auto it = as.maps().begin(); it != as.maps().end(); ++it) {
    AddressSpace::Mapping m = *it;
    string raw_map_line = m.map.str();

    if (!checksum_segment_filter(m)) {
      fprintf(checksums_file, "(%x) %s\n", ignored_checksum,
              raw_map_line.c_str());
      continue;
    }

    vector<uint8_t> mem;
    mem.resize(m.map.size());
    memset(mem.data(), 0, mem.size());
    ssize_t valid_mem_len =
        t->read_bytes_fallible(m.map.start(), mem.size(), mem.data());
    /* Areas not read are treated as zero. We have to do this because
       mappings not backed by valid file data are not readable during
       recording but are read as 0 during replay. */
    if (valid_mem_len < 0) {
      /* It is possible for whole mappings to be beyond the extent of the
       * backing file, in which case read_bytes_fallible will return -1.
       */
      ASSERT(t, valid_mem_len == -1 && errno == EIO);
    }

    if (m.flags & AddressSpace::Mapping::IS_SYSCALLBUF) {
      normalize_syscallbuf(t, mem);
    }

    uint32_t checksum = compute_checksum(mem.data(), mem.size());
    fprintf(checksums_file, "(%x) %s\n", checksum, raw_map_line.c_str());
  }

  fclose(checksums_file);
}

void validate_process_memory(ReplayTask* t, FrameTime global_time) {
  string filename = format_dump_filename(t, global_time, "mem_checksums");
  FILE* checksums_file = fopen64(filename.c_str(), "r");
  if (!checksums_file) {
    FATAL() << "Failed to open checksum file " << filename;
  }

  remote_ptr<unsigned char> in_replay_flag;
  if (t->session().has_trace_quirk(TraceReader::UsesGlobalsInReplay) && t->preload_globals) {
    in_replay_flag = REMOTE_PTR_FIELD(t->preload_globals, reserved_legacy_in_replay);
    t->write_mem(in_replay_flag, (unsigned char)0);
  }

  while (true) {
    char line[1024];
    if (!fgets(line, sizeof(line), checksums_file)) {
      break;
    }
    unsigned int checksum;
    unsigned long start;
    unsigned long end;
    int nparsed = sscanf(line, "(%x) %lx-%lx", &checksum, &start, &end);
    ASSERT(t, 3 == nparsed) << "Parsed " << nparsed << " items";

    if (is_start_of_scratch_region(t, start)) {
      /* Replay doesn't touch scratch regions, so
       * their contents are allowed to diverge.
       * Tracees can't observe those segments unless
       * they do something sneaky (or disastrously
       * buggy). */
      LOG(debug) << "Not validating scratch starting at " << start;
      continue;
    }

    if (checksum == ignored_checksum) {
      LOG(debug) << "Checksum not computed during recording";
      continue;
    }
    if (checksum == sigbus_checksum) {
      continue;
    }

    vector<uint8_t> mem;
    mem.resize(end - start);
    memset(mem.data(), 0, mem.size());
    t->read_bytes_fallible(start, mem.size(), mem.data());

    const AddressSpace::Mapping& m = t->vm()->mapping_of(start);

    if (m.flags & AddressSpace::Mapping::IS_SYSCALLBUF) {
      normalize_syscallbuf(t, mem);
    }

    uint32_t our_checksum = compute_checksum(mem.data(), mem.size());

    if (checksum != our_checksum) {
      notify_checksum_error(t, global_time, our_checksum, checksum,
                            m.map.str());
    }
  }

  if (in_replay_flag) {
    t->write_mem(in_replay_flag, (unsigned char)1);
  }

  fclose(checksums_file);
}

signal_action default_action(int sig) {
  if (32 <= sig && sig <= 64) {
    return TERMINATE;
  }
  switch (sig) {
/* TODO: SSoT for signal defs/semantics. */
#define CASE(_sig, _act)                                                       \
  case SIG##_sig:                                                              \
    return _act
    CASE(HUP, TERMINATE);
    CASE(INT, TERMINATE);
    CASE(QUIT, DUMP_CORE);
    CASE(ILL, DUMP_CORE);
    CASE(ABRT, DUMP_CORE);
    CASE(FPE, DUMP_CORE);
    CASE(KILL, TERMINATE);
    CASE(SEGV, DUMP_CORE);
    CASE(PIPE, TERMINATE);
    CASE(ALRM, TERMINATE);
    CASE(TERM, TERMINATE);
    CASE(USR1, TERMINATE);
    CASE(USR2, TERMINATE);
    CASE(CHLD, IGNORE);
    CASE(CONT, CONTINUE);
    CASE(STOP, STOP);
    CASE(TSTP, STOP);
    CASE(TTIN, STOP);
    CASE(TTOU, STOP);
    CASE(BUS, DUMP_CORE);
    /*CASE(POLL, TERMINATE);*/
    CASE(PROF, TERMINATE);
    CASE(SYS, DUMP_CORE);
    CASE(TRAP, DUMP_CORE);
    CASE(URG, IGNORE);
    CASE(VTALRM, TERMINATE);
    CASE(XCPU, DUMP_CORE);
    CASE(XFSZ, DUMP_CORE);
    /*CASE(IOT, DUMP_CORE);*/
    /*CASE(EMT, TERMINATE);*/
    CASE(STKFLT, TERMINATE);
    CASE(IO, TERMINATE);
    CASE(PWR, TERMINATE);
    /*CASE(LOST, TERMINATE);*/
    CASE(WINCH, IGNORE);
    default:
      FATAL() << "Unknown signal " << sig;
      return TERMINATE; // not reached
#undef CASE
  }
}

SignalDeterministic is_deterministic_signal(Task* t) {
  const siginfo_t& si = t->get_siginfo();
  switch (si.si_signo) {
    /* These signals may be delivered deterministically;
     * we'll check for sure below. */
    case SIGILL:
    case SIGBUS:
    case SIGFPE:
    case SIGSEGV:
      /* As bits/siginfo.h documents,
       *
       *   Values for `si_code'.  Positive values are
       *   reserved for kernel-generated signals.
       *
       * So if the signal is maybe-synchronous, and the
       * kernel delivered it, then it must have been
       * delivered deterministically. */
      return si.si_code > 0 ? DETERMINISTIC_SIG : NONDETERMINISTIC_SIG;
    case SIGTRAP: {
      // The kernel code is wrong about this one. It treats singlestep
      // traps as deterministic, but they aren't. PTRACE_ATTACH traps aren't
      // really deterministic either.
      auto reasons = t->compute_trap_reasons();
      return reasons.breakpoint || reasons.watchpoint ? DETERMINISTIC_SIG
                                                      : NONDETERMINISTIC_SIG;
    }
    default:
      /* All other signals can never be delivered
       * deterministically (to the approximation required by
       * rr). */
      return NONDETERMINISTIC_SIG;
  }
}

static bool is_tmp_file(const ScopedFd &fd, const string &tracee_path) {
  if (getenv("RR_TRUST_TEMP_FILES")) {
    return false;
  }
  struct statfs sfs;
  int ret = fstatfs(fd.get(), &sfs);
  return ((ret == 0 && TMPFS_MAGIC == sfs.f_type)
          // In observed configurations of Ubuntu 13.10, /tmp is
          // a folder in the / fs, not a separate tmpfs.
          || tracee_path.c_str() == strstr(tracee_path.c_str(), "/tmp/"));
}

bool should_copy_mmap_region(const KernelMapping& mapping,
                             const string &file_name,
                             const struct stat& stat) {
  if (getenv("RR_COPY_ALL_FILES")) {
    return true;
  }

  int flags = mapping.flags();
  int prot = mapping.prot();
  bool private_mapping = (flags & MAP_PRIVATE);

  // file_name may point into proc, since we may not have direct access to
  // the file. Open it, so we can perform the various queries we'd like to ask.
  ScopedFd fd(file_name.c_str(), O_RDONLY);

  // TODO: handle mmap'd files that are unlinked during
  // recording or otherwise not available.
  if (!fd.is_open()) {
    // This includes files inaccessible because the tracee is using a different
    // mount namespace with its own mounts
    // It's also possible for a tracee to mmap a file it doesn't have permission
    // to read, e.g. if a daemon opened the file and passed the fd over a
    // socket. We should copy the data now because we won't be able to read
    // it later. nscd does this.
    LOG(debug) << "  copying unlinked/inaccessible file";
    return true;
  }
  if (!S_ISREG(stat.st_mode)) {
    LOG(debug) << "  copying non-regular-file";
    return true;
  }
  if (is_tmp_file(fd, mapping.fsname())) {
    LOG(debug) << "  copying file on tmpfs";
    return true;
  }
  if (mapping.fsname() == "/etc/ld.so.cache") {
    // This file changes on almost every system update so we should copy it.
    LOG(debug) << "  copying " << mapping.fsname();
    return true;
  }
  if (mapping.fsname().rfind("/etc/passwd", 0) == 0 ||
      mapping.fsname().rfind("/etc/group", 0) == 0) {
    // These files (and suffixes such as .cache etc) change very frequently in
    // some environments.
    LOG(debug) << "  copying " << mapping.fsname();
    return true;
  }
  if (private_mapping && (prot & PROT_EXEC)) {
    /* Be optimistic about private executable mappings */
    LOG(debug) << "  (no copy for +x private mapping " << mapping.fsname() << ")";
    return false;
  }
  if (private_mapping && (0111 & stat.st_mode)) {
    /* A private mapping of an executable file usually
     * indicates mapping data sections of object files.
     * Since we're already assuming those change very
     * infrequently, we can avoid copying the data
     * sections too. */
    LOG(debug) << "  (no copy for private mapping of +x " << mapping.fsname() << ")";
    return false;
  }

  // TODO: using "can the euid of the rr process write this
  // file" as an approximation of whether the tracee can write
  // the file.  If the tracee is messing around with
  // set*[gu]id(), the real answer may be different.
  bool can_write_file = (0 == access(file_name.c_str(), W_OK));

  // Inside a user namespace, the real root user may be mapped to UID 65534.
  if (!can_write_file && (0 == stat.st_uid || 65534 == stat.st_uid)) {
    // We would like to DEBUG_ASSERT this, but on Ubuntu 13.10,
    // the file /lib/i386-linux-gnu/libdl-2.17.so is
    // writeable by root for unknown reasons.
    // DEBUG_ASSERT(!(prot & PROT_WRITE));
    /* Mapping a file owned by root: we don't care if this
     * was a PRIVATE or SHARED mapping, because unless the
     * program is disastrously buggy or unlucky, the
     * mapping is effectively PRIVATE.  Bad luck can come
     * from this program running during a system update,
     * or a user being added, which is probably less
     * frequent than even system updates.
     *
     * XXX what about the fontconfig cache files? */
    LOG(debug) << "  (no copy for root-owned " << mapping.fsname() << ")";
    return false;
  }
  if (private_mapping) {
    /* Some programs (at least Firefox) have been observed
     * to use cache files that are expected to be
     * consistent and unchanged during the bulk of
     * execution, but may be destroyed or mutated at
     * shutdown in preparation for the next session.  We
     * don't otherwise know what to do with private
     * mappings, so err on the safe side.
     *
     * TODO: could get into dirty heuristics here like
     * trying to match "cache" in the filename ... */
    LOG(debug) << "  copying private mapping of non-system -x " << file_name;
    return true;
  }
  if (!(0222 & stat.st_mode)) {
    /* We couldn't write the file because it's read only.
     * But it's not a root-owned file (therefore not a
     * system file), so it's likely that it could be
     * temporary.  Copy it. */
    LOG(debug) << "  copying read-only, non-system file";
    return true;
  }
  if (!can_write_file) {
    /* mmap'ing another user's (non-system) files?  Highly
     * irregular ... */
    LOG(warn) << "Scary mmap " << file_name << "(prot:" << HEX(prot)
              << ((flags & MAP_SHARED) ? ";SHARED" : "")
              << "); uid:" << stat.st_uid << " mode:" << stat.st_mode;
  }
  return true;
}

void resize_shmem_segment(ScopedFd& fd, uint64_t num_bytes) {
  if (ftruncate(fd, num_bytes)) {
    FATAL() << "Failed to resize shmem to " << num_bytes;
  }
}

bool xsave_enabled() {
  CPUIDData features = cpuid(CPUID_GETFEATURES, 0);
  return (features.ecx & OSXSAVE_FEATURE_FLAG) != 0;
}


#define FATAL_X86_ONLY() FATAL() << "Reached x86-only code on non-x86 arch"

uint64_t xcr0() {
#if defined(__i386__) || defined(__x86_64__)
  if (!xsave_enabled()) {
    // Assume x87/SSE enabled.
    return 3;
  }
  uint32_t eax, edx;
  asm volatile("xgetbv"
               : "=a"(eax), "=d"(edx)
               : "c"(0));
  return (uint64_t(edx) << 32) | eax;
#else
  FATAL_X86_ONLY();
  return 0;
#endif
}

#if defined(__i386__) || defined(__x86_64__)
CPUIDData cpuid(uint32_t code, uint32_t subrequest) {
  CPUIDData result;
  asm volatile("cpuid"
               : "=a"(result.eax), "=b"(result.ebx), "=c"(result.ecx),
                 "=d"(result.edx)
               : "a"(code), "c"(subrequest));
  return result;
}
#else
CPUIDData cpuid(uint32_t, uint32_t) {
  FATAL_X86_ONLY();
  __builtin_unreachable();
}
#endif


#define SEGV_HANDLER_MAGIC 0x98765432

static void cpuid_segv_handler(__attribute__((unused)) int sig,
                               __attribute__((unused)) siginfo_t* si,
                               void* user) {
#if defined(__i386__)
  ucontext_t* ctx = (ucontext_t*)user;
  ctx->uc_mcontext.gregs[REG_EIP] += 2;
  ctx->uc_mcontext.gregs[REG_EAX] = SEGV_HANDLER_MAGIC;
#elif defined(__x86_64__)
  ucontext_t* ctx = (ucontext_t*)user;
  ctx->uc_mcontext.gregs[REG_RIP] += 2;
  ctx->uc_mcontext.gregs[REG_RAX] = SEGV_HANDLER_MAGIC;
#else
  (void)user;
  FATAL_X86_ONLY();
#endif
}

static CPUIDRecord cpuid_record(uint32_t eax, uint32_t ecx) {
  CPUIDRecord result = { eax, ecx, cpuid(eax, ecx) };
  return result;
}

bool is_cpu_vendor_amd(CPUIDData vendor_string)
{
  char vendor[12];
  memcpy(&vendor[0], &vendor_string.ebx, 4);
  memcpy(&vendor[4], &vendor_string.edx, 4);
  memcpy(&vendor[8], &vendor_string.ecx, 4);
  return strncmp(vendor, "AuthenticAMD", sizeof(vendor)) == 0;
}

static vector<CPUIDRecord> gather_cpuid_records(uint32_t up_to) {
  vector<CPUIDRecord> results;
  CPUIDRecord vendor_string = cpuid_record(CPUID_GETVENDORSTRING, UINT32_MAX);
  results.push_back(vendor_string);
  uint32_t basic_info_max = min(up_to, vendor_string.out.eax);
  bool has_SGX = false;
  bool has_hypervisor = false;

  for (uint32_t base = 1; base <= basic_info_max; ++base) {
    switch (base) {
      case CPUID_GETCACHEPARAMS:
        for (int level = 0;; ++level) {
          CPUIDRecord rec = cpuid_record(base, level);
          results.push_back(rec);
          if (!(rec.out.eax & 0x1f)) {
            // Cache Type Field == no more caches
            break;
          }
        }
        break;
      case CPUID_GETEXTENDEDFEATURES: {
        CPUIDRecord rec = cpuid_record(base, 0);
        results.push_back(rec);
        if (rec.out.ebx & 0x4) {
          has_SGX = true;
        }
        for (uint32_t level = 1; level <= rec.out.eax; ++level) {
          results.push_back(cpuid_record(base, level));
        }
        break;
      }
      case CPUID_GETEXTENDEDTOPOLOGY: {
        for (int level = 0;; ++level) {
          CPUIDRecord rec = cpuid_record(base, level);
          results.push_back(rec);
          if (!(rec.out.ecx & 0xff00)) {
            // Level Type == 0
            break;
          }
        }
        break;
      }
      case CPUID_GETXSAVE:
        for (uint32_t level = 0; level < 64; ++level) {
          results.push_back(cpuid_record(base, level));
        }
        break;
      case CPUID_GETRDTMONITORING: {
        CPUIDRecord rec = cpuid_record(base, 0);
        results.push_back(rec);
        for (uint32_t level = 1; level < 64; ++level) {
          if (rec.out.edx & (1LL << level)) {
            results.push_back(cpuid_record(base, level));
          }
        }
        break;
      }
      case CPUID_GETRDTALLOCATION: {
        CPUIDRecord rec = cpuid_record(base, 0);
        results.push_back(rec);
        for (uint32_t level = 1; level < 64; ++level) {
          if (rec.out.ebx & (1LL << level)) {
            results.push_back(cpuid_record(base, level));
          }
        }
        break;
      }
      case CPUID_GETSGX:
        results.push_back(cpuid_record(base, 0));
        if (has_SGX) {
          results.push_back(cpuid_record(base, 1));
          for (int level = 2;; ++level) {
            CPUIDRecord rec = cpuid_record(base, level);
            results.push_back(rec);
            if (!(rec.out.eax & 0x0f)) {
              // Sub-leaf Type == 0
              break;
            }
          }
        }
        break;
      case CPUID_GETPT:
      case CPUID_GETSOC: {
        CPUIDRecord rec = cpuid_record(base, 0);
        results.push_back(rec);
        for (uint32_t level = 1; level <= rec.out.eax; ++level) {
          results.push_back(cpuid_record(base, level));
        }
        break;
      }
      case CPUID_GETFEATURES: {
        CPUIDRecord rec = cpuid_record(base, UINT32_MAX);
        results.push_back(rec);
        if (rec.out.ecx & (1 << 31)) {
          has_hypervisor = true;
        }
        break;
      }
      default:
        results.push_back(cpuid_record(base, UINT32_MAX));
        break;
    }
  }

  if (up_to < CPUID_HYPERVISOR) {
    return results;
  }

  if (has_hypervisor) {
    CPUIDRecord hv_info = cpuid_record(CPUID_HYPERVISOR, UINT32_MAX);
    results.push_back(hv_info);
    int hv_info_max = min(up_to, hv_info.out.eax);
    for (int extended = CPUID_HYPERVISOR + 1; extended <= hv_info_max;
         ++extended) {
      results.push_back(cpuid_record(extended, UINT32_MAX));
    }
  }

  if (up_to < CPUID_INTELEXTENDED) {
    return results;
  }

  bool is_amd = is_cpu_vendor_amd(vendor_string.out);

  CPUIDRecord extended_info = cpuid_record(CPUID_INTELEXTENDED, UINT32_MAX);
  results.push_back(extended_info);
  uint32_t extended_info_max = min(up_to, extended_info.out.eax);
  for (uint32_t extended = CPUID_INTELEXTENDED + 1; extended <= extended_info_max;
       ++extended) {
    if (is_amd) {
      if (extended == CPUID_AMD_CACHE_TOPOLOGY) {
        for (int level = 0;; ++level) {
          CPUIDRecord rec = cpuid_record(extended, level);
          results.push_back(rec);
          if (!(rec.out.eax & 0x1f)) {
            // CacheType: null, no more caches
            break;
          }
        }
        continue;
      } else if (extended == CPUID_AMD_PLATFORM_QOS) {
        cpuid_record(extended, 0);
        cpuid_record(extended, 1);
        continue;
      }
    }
    results.push_back(cpuid_record(extended, UINT32_MAX));
  }

  return results;
}

vector<CPUIDRecord> all_cpuid_records() {
  return gather_cpuid_records(UINT32_MAX);
}

#ifdef SYS_arch_prctl
#define RR_ARCH_PRCTL(a, b) syscall(SYS_arch_prctl, a, b)
#else
#define RR_ARCH_PRCTL(a, b) ((void)a, (void)b, -1)
#endif

bool cpuid_faulting_works() {
  static bool did_check_cpuid_faulting = false;
  static bool cpuid_faulting_ok = false;

  if (did_check_cpuid_faulting) {
    return cpuid_faulting_ok;
  }
  did_check_cpuid_faulting = true;

  // Test to see if CPUID faulting works.
  if (RR_ARCH_PRCTL(ARCH_SET_CPUID, 0L) != 0) {
    LOG(debug) << "CPUID faulting not supported by kernel/hardware";
    return false;
  }

  // Some versions of Xen seem to set the feature bit but the feature doesn't
  // actually work, so we need to test it.
  struct sigaction sa;
  struct sigaction old_sa;
  sa.sa_sigaction = cpuid_segv_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  if (sigaction(SIGSEGV, &sa, &old_sa) < 0) {
    FATAL() << "Can't set sighandler";
  }

  CPUIDData data = cpuid(CPUID_GETVENDORSTRING, 0);
  if (data.eax == SEGV_HANDLER_MAGIC) {
    LOG(debug) << "CPUID faulting works";
    cpuid_faulting_ok = true;
  } else {
    LOG(debug) << "CPUID faulting advertised but does not work";
  }

  if (sigaction(SIGSEGV, &old_sa, NULL) < 0) {
    FATAL() << "Can't restore sighandler";
  }
  if (RR_ARCH_PRCTL(ARCH_SET_CPUID, 1L) < 0) {
    FATAL() << "Can't restore ARCH_SET_CPUID";
  }
  return cpuid_faulting_ok;
}

const CPUIDRecord* find_cpuid_record(const vector<CPUIDRecord>& records,
                                     uint32_t eax, uint32_t ecx) {
  for (const auto& rec : records) {
    if (rec.eax_in == eax && (rec.ecx_in == ecx || rec.ecx_in == UINT32_MAX)) {
      return &rec;
    }
  }
  return nullptr;
}

bool cpuid_compatible(const vector<CPUIDRecord>& trace_records) {
  // We could compare all CPUID records but that might be fragile (it's hard to
  // be sure the values don't change in ways applications don't care about).
  // Let's just check the microarch for now.
  auto cpuid_data = cpuid(CPUID_GETFEATURES, 0);
  unsigned int cpu_type = cpuid_data.eax & 0xF0FF0;
  auto trace_cpuid_data =
      find_cpuid_record(trace_records, CPUID_GETFEATURES, 0);
  if (!trace_cpuid_data) {
    FATAL() << "GETFEATURES missing???";
  }
  unsigned int trace_cpu_type = trace_cpuid_data->out.eax & 0xF0FF0;
  return cpu_type == trace_cpu_type;
}

bool cpu_has_xsave_fip_fdp_quirk() {
  CPUIDData features = cpuid(CPUID_GETFEATURES, 0);
  if ((features.ecx & XSAVE_FEATURE_FLAG) == 0) {
    return false;
  }
#if defined(__i386__) || defined(__x86_64__)
  uint64_t xsave_buf[576/sizeof(uint64_t)] __attribute__((aligned(64)));
  xsave_buf[1] = 0;
  asm volatile("finit\n"
               "fld1\n"
#if defined(__x86_64__)
               "xsave64 %0\n"
#else
               "xsave %0\n"
#endif
               : "=m"(xsave_buf)
               : "a"(1), "d"(0)
               : "memory");
  return !xsave_buf[1];
#else
  FATAL_X86_ONLY();
  return false;
#endif
}

bool cpu_has_fdp_exception_only_quirk() {
#if defined(__i386__) || defined(__x86_64__)
  uint32_t fenv_buf[7];
  fenv_buf[5] = 0;
  asm volatile("finit\n"
               "fld1\n"
               "fstenv %0\n"
               : "=m"(fenv_buf)
               :
               : "memory");
  return !fenv_buf[5];
#else
  FATAL_X86_ONLY();
  return false;
#endif
}

template <typename Arch>
static CloneParameters extract_clone_parameters_arch(const Registers& regs) {
  CloneParameters result;
  result.stack = regs.arg2();
  result.ptid = regs.arg3();
  switch (Arch::clone_parameter_ordering) {
    case Arch::FlagsStackParentTLSChild:
      result.tls = regs.arg4();
      result.ctid = regs.arg5();
      break;
    case Arch::FlagsStackParentChildTLS:
      result.tls = regs.arg5();
      result.ctid = regs.arg4();
      break;
  }
  int flags = (int)regs.orig_arg1();
  // If these flags aren't set, the corresponding clone parameters may be
  // invalid pointers, so make sure they're ignored.
  if (!(flags & (CLONE_PARENT_SETTID | CLONE_PIDFD))) {
    result.ptid = nullptr;
  }
  if (!(flags & (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID))) {
    result.ctid = nullptr;
  }
  if (!(flags & CLONE_SETTLS)) {
    result.tls = nullptr;
  }
  return result;
}

CloneParameters extract_clone_parameters(Task* t) {
  RR_ARCH_FUNCTION(extract_clone_parameters_arch, t->arch(), t->regs());
}

int read_elf_class(const string& filename) {
  ScopedFd fd(filename.c_str(), O_RDONLY);
  if (!fd.is_open()) {
    return NOT_ELF;
  }
  char elf_header[EI_CLASS + 1];
  static const char magic[4] = { ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3 };
  if (read(fd, elf_header, sizeof(elf_header)) != sizeof(elf_header) ||
      memcmp(magic, elf_header, sizeof(magic)) != 0) {
    return NOT_ELF;
  }
  return elf_header[EI_CLASS];
}

// Setting these causes us to trace instructions after
// instruction_trace_at_event_start up to and including
// instruction_trace_at_event_last
static FrameTime instruction_trace_at_event_start = 0;
static FrameTime instruction_trace_at_event_last = 0;

bool trace_instructions_up_to_event(FrameTime event) {
  return event > instruction_trace_at_event_start &&
         event <= instruction_trace_at_event_last;
}

void dump_task_set(const set<Task*>& tasks) {
  printf("[");
  for (auto& t : tasks) {
    printf("%p (pid=%d, rec=%d),", t, t->tid, t->rec_tid);
  }
  printf("]\n");
}

void dump_task_map(const map<pid_t, Task*>& tasks) {
  printf("[");
  for (auto& t : tasks) {
    printf("%p (pid=%d, rec=%d),", t.second, t.second->tid, t.second->rec_tid);
  }
  printf("]\n");
}

string real_path(const string& path) {
  char buf[PATH_MAX];
  if (realpath(path.c_str(), buf) == buf) {
    return string(buf);
  }
  return path;
}

static string read_exe_dir() {
  KernelMapping km =
      AddressSpace::read_local_kernel_mapping((uint8_t*)&read_exe_dir);
  string exe_path = km.fsname();
  int end = exe_path.length();
  // Chop off the filename
  while (end > 0 && exe_path[end - 1] != '/') {
    --end;
  }
  exe_path.erase(end);
  return exe_path;
}

string resource_path() {
  string resource_path = Flags::get().resource_path;
  if (resource_path.empty()) {
    static string exe_path = read_exe_dir() + "../";
    return exe_path;
  }
  return resource_path;
}

/**
 * Get the current time from the preferred monotonic clock in units of
 * seconds, relative to an unspecific point in the past.
 */
double monotonic_now_sec() {
  struct timespec tp;
  clock_gettime(CLOCK_MONOTONIC, &tp);
  return (double)tp.tv_sec + (double)tp.tv_nsec / 1e9;
}

bool running_under_rr(bool cache) {
  static bool rr_under_rr = false;
  static bool rr_check_done = false;
  if (!rr_check_done || !cache) {
    rr_check_done = true;
    int ret = syscall(SYS_rrcall_check_presence, (uintptr_t)0, (uintptr_t)0,
      (uintptr_t)0, (uintptr_t)0, (uintptr_t)0, (uintptr_t)0);
    if (ret > 0 || (ret < 0 && errno != ENOSYS)) {
      FATAL() << "Unexpected result for rrcall_check_presence: " << ret;
    }
    rr_under_rr = ret == 0;
  }
  return rr_under_rr;
}

string find_helper_library(const char *basepath)
{
  string lib_path = resource_path() + "lib64/rr/";
  string file_name = lib_path + basepath;
  if (access(file_name.c_str(), F_OK) == 0) {
    return lib_path;
  }
  lib_path = resource_path() + "lib/rr/";
  file_name = lib_path + basepath;
  if (access(file_name.c_str(), F_OK) == 0) {
    return lib_path;
  }
  // File does not exist. Assume install put it in LD_LIBRARY_PATH.
  lib_path = "";
  return lib_path;
}

vector<string> read_proc_status_fields(pid_t tid, const char* name,
                                       const char* name2, const char* name3) {
  vector<string> result;
  FILE *f;
  char buf[1000];
  if (tid == 0) {
    f = fopen("/proc/self/status", "r");
  } else {
    sprintf(buf, "/proc/%d/status", tid);
    f = fopen(buf, "r");
  }
  if (!f) {
    return result;
  }
  vector<string> matches;
  matches.push_back(string(name) + ":");
  if (name2) {
    matches.push_back(string(name2) + ":");
  }
  if (name3) {
    matches.push_back(string(name3) + ":");
  }
  for (auto& m : matches) {
    while (true) {
      if (!fgets(buf, sizeof(buf), f)) {
        break;
      }
      if (strncmp(buf, m.c_str(), m.size()) == 0) {
        char* b = buf + m.size();
        while (*b == ' ' || *b == '\t') {
          ++b;
        }
        char* e = b;
        while (*e && *e != '\n') {
          ++e;
        }
        result.push_back(string(b, e - b));
        break;
      }
    }
  }
  fclose(f);
  return result;
}

static bool check_for_pax_kernel() {
  auto results = read_proc_status_fields(getpid(), "PaX");
  return !results.empty();
}

bool uses_invisible_guard_page() {
  static bool is_pax_kernel = check_for_pax_kernel();
  return !is_pax_kernel;
}

bool read_proc_net_socket_addresses(Task* t, int fd,
                                    std::array<typename NativeArch::sockaddr_storage, 2> &out) {
  char buf[1000];

  auto stat = t->stat_fd(fd);
  ino_t inode = stat.st_ino;

  // Check tcp first.
  if (FILE* f = fopen("/proc/net/tcp", "r")) {
    // Skip the first line, which contains human-readable column labels.
    if (!fgets(buf, sizeof(buf) - 1, f)) {
      LOG(warn) << "Can't read /proc/net/tcp";
    }
    while (fgets(buf, sizeof(buf) - 1, f)) {
      // Ignore the first field.
      strtok(buf, " ");
      // Then come the local and remote addresses.
      char* local_addr_str = strtok(NULL, " ");
      char* remote_addr_str = strtok(NULL, " ");
      // Then six more fields to ignore.
      strtok(NULL, " ");
      strtok(NULL, " ");
      strtok(NULL, " ");
      strtok(NULL, " ");
      strtok(NULL, " ");
      strtok(NULL, " ");
      // Finally the inode
      char* ino = strtok(NULL, " ");
      ino_t inod = strtoull(ino, NULL, 10);
      if (inod != inode) {
        continue;
      }

      // We have a match.
      char* next = NULL;
      unsigned long laddr = strtoul(local_addr_str, &next, 16);
      if ((laddr == ULONG_MAX && errno == ERANGE) || *next != ':') {
        LOG(warn) << "Local address not in expected format";
        break;
      }
      ++next;
      unsigned long lport = strtoul(next, NULL, 16);
      if (lport > USHRT_MAX) {
        LOG(warn) << "Local address not in expected format";
        break;
      }
      struct sockaddr_in* local_addr_in = (struct sockaddr_in*)&out[0];
      local_addr_in->sin_family = AF_INET;
      local_addr_in->sin_addr.s_addr = laddr;
      local_addr_in->sin_port = lport;
      unsigned long raddr = strtoul(remote_addr_str, &next, 16);
      if ((raddr == ULONG_MAX && errno == ERANGE) || *next != ':') {
        LOG(warn) << "Remote address not in expected format";
        break;
      }
      ++next;
      unsigned long rport = strtoul(next, NULL, 16);
      if (rport > USHRT_MAX) {
        LOG(warn) << "Remote address not in expected format";
        break;
      }
      struct sockaddr_in* remote_addr_in = (struct sockaddr_in*)&out[1];
      remote_addr_in->sin_family = AF_INET;
      remote_addr_in->sin_addr.s_addr = raddr;
      remote_addr_in->sin_port = rport;
      fclose(f);
      return true;
    }
    fclose(f);
  } else {
    LOG(warn) << "Can't open /proc/net/tcp";
  }

  // Then tcp6
  if (FILE* f = fopen("/proc/net/tcp6", "r")) {
    // Skip the first line, which contains human-readable column labels.
    if (!fgets(buf, sizeof(buf) - 1, f)) {
      LOG(warn) << "Can't read /proc/net/tcp6";
    }
    while (fgets(buf, sizeof(buf) - 1, f)) {
      // Ignore the first field.
      strtok(buf, " ");
      // Then come the local and remote addresses.
      char* local_addr_str = strtok(NULL, " ");
      char* remote_addr_str = strtok(NULL, " ");
      // Then six more fields to ignore.
      strtok(NULL, " ");
      strtok(NULL, " ");
      strtok(NULL, " ");
      strtok(NULL, " ");
      strtok(NULL, " ");
      strtok(NULL, " ");
      // Finally the inode
      char* ino = strtok(NULL, " ");
      ino_t inod = strtoull(ino, NULL, 10);
      if (inod != inode) {
        continue;
      }

      // We have a match.
      struct sockaddr_in6* local_addr_in6 = (struct sockaddr_in6*)&out[0];
      local_addr_in6->sin6_family = AF_INET6;

      if (strlen(local_addr_str) != 37) {
        break;
      }
      char buf[9];
      for (int i = 0; i < 4; ++i) {
        char* c = local_addr_str + i * 8;
        strncpy(buf, c, 8);
        buf[8] = '\0';
        unsigned long local_addr_component = strtoul(buf, NULL, 16);
        if ((local_addr_component == ULONG_MAX && errno == ERANGE)) {
          LOG(warn) << "Local address not in expected format";
          break;
        }
        local_addr_in6->sin6_addr.s6_addr32[i] = local_addr_component;
      }
      if (*(local_addr_str + 32) != ':') {
        LOG(warn) << "Local address not in expected format";
        break;
      }
      unsigned long lport = strtoul(local_addr_str + 33, NULL, 16);
      if (lport > USHRT_MAX) {
        LOG(warn) << "Local address not in expected format";
        break;
      }
      local_addr_in6->sin6_port = lport;

      struct sockaddr_in6* remote_addr_in6 = (struct sockaddr_in6*)&out[1];
      remote_addr_in6->sin6_family = AF_INET6;

      if (strlen(remote_addr_str) != 37) {
        break;
      }
      for (int i = 0; i < 4; ++i) {
        char* c = remote_addr_str + 24 - i * 8;
        strncpy(buf, c, 8);
        buf[8] = '\0';
        unsigned long remote_addr_component = strtoul(buf, NULL, 16);
        if ((remote_addr_component == ULONG_MAX && errno == ERANGE)) {
          LOG(warn) << "Remote address not in expected format";
          break;
        }
        remote_addr_in6->sin6_addr.s6_addr32[i] = remote_addr_component;
      }
      if (*(remote_addr_str + 32) != ':') {
        LOG(warn) << "Remote address not in expected format";
        break;
      }
      unsigned long rport = strtoul(remote_addr_str + 33, NULL, 16);
      if (rport > USHRT_MAX) {
        LOG(warn) << "Remote address not in expected format";
        break;
      }
      remote_addr_in6->sin6_port = rport;
      fclose(f);
      return true;
    }
    fclose(f);
  } else {
    LOG(warn) << "Can't open /proc/net/tcp6";
  }

  return false;
}

static bool try_copy_file_by_copy_all(int dest_fd, int src_fd)
{
  static bool should_try_copy_all = true;
  if (!should_try_copy_all) {
    return false;
  }
  struct stat src_stat;
  if (0 != fstat(src_fd, &src_stat)) {
    return false;
  }
  size_t remaining_size = src_stat.st_size;
  while (remaining_size > 0) {
    ssize_t ncopied = syscall(NativeArch::copy_file_range, src_fd, NULL,
                              dest_fd, NULL, remaining_size, 0);
    if (ncopied == -1) {
      if (errno == ENOSYS) {
        should_try_copy_all = false;
      }
      return false;
    }
    if (ncopied == 0) {
      // This doesn't necessarily mean EOF - some file systems don't like this
      // system call.
      return false;
    }
    remaining_size -= ncopied;
  }
  return true;
}

bool copy_file(int dest_fd, int src_fd) {
  char buf[32 * 1024];
  if (try_copy_file_by_copy_all(dest_fd, src_fd)) {
    return true;
  }
  while (1) {
    ssize_t bytes_read = read(src_fd, buf, sizeof(buf));
    if (bytes_read < 0) {
      return false;
    }
    if (!bytes_read) {
      break;
    }
    write_all(dest_fd, buf, bytes_read);
  }
  return true;
}

bool has_effective_caps(uint64_t caps) {
  struct NativeArch::cap_header header = {.version =
                                              _LINUX_CAPABILITY_VERSION_3,
                                          .pid = 0 };
  struct NativeArch::cap_data data[_LINUX_CAPABILITY_U32S_3];
  if (syscall(NativeArch::capget, &header, data) != 0) {
    FATAL() << "FAILED to read capabilities";
  }
  for (int i = 0; i < _LINUX_CAPABILITY_U32S_3; ++i) {
    if ((data[i].effective & (uint32_t)caps) != (uint32_t)caps) {
      return false;
    }
    caps >>= 32;
  }
  return true;
}

const XSaveLayout& xsave_native_layout() {
  static XSaveLayout layout =
      xsave_layout_from_trace(gather_cpuid_records(CPUID_GETXSAVE));
  return layout;
}

XSaveLayout xsave_layout_from_trace(const std::vector<CPUIDRecord> records) {
  XSaveLayout layout;

  size_t record_index;
  for (record_index = 0; record_index < records.size(); ++record_index) {
    if (records[record_index].eax_in == CPUID_GETXSAVE) {
      break;
    }
  }
  if (record_index >= records.size()) {
    // XSAVE not present
    layout.full_size = 512;
    // x87/XMM always supported
    layout.supported_feature_bits = 0x3;
    return layout;
  }

  CPUIDRecord cpuid_data = records[record_index];
  DEBUG_ASSERT(cpuid_data.ecx_in == 0);
  layout.full_size = cpuid_data.out.ebx;
  layout.supported_feature_bits =
      cpuid_data.out.eax | (uint64_t(cpuid_data.out.edx) << 32);

  for (size_t i = 2; i < 64; ++i) {
    if (layout.supported_feature_bits & (uint64_t(1) << i)) {
      do {
        ++record_index;
        if (record_index >= records.size() ||
            records[record_index].eax_in != CPUID_GETXSAVE) {
          FATAL() << "Missing CPUID record for feature " << i;
        }
      } while (records[record_index].ecx_in != i);
      cpuid_data = records[record_index];
      while (layout.feature_layouts.size() < i) {
        layout.feature_layouts.push_back({ 0, 0 });
      }
      layout.feature_layouts.push_back(
          { cpuid_data.out.ebx, cpuid_data.out.eax });
    }
  }
  return layout;
}

static const char localhost_addr[] = "127.0.0.1";
static const char localhost_addr_ipv6[] = "::1";

// `addr` must be the right size for for the given domain
static bool get_address(int domain, const string& host, struct sockaddr* addr) {
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = domain;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  struct addrinfo* ret;
  if (getaddrinfo(host.c_str(), nullptr, &hints, &ret) != 0) {
    return false;
  }
  memcpy(addr, ret->ai_addr, ret->ai_addrlen);
  freeaddrinfo(ret);
  return true;
}

OpenedSocket open_socket(const string& host, unsigned short port,
                         ProbePort probe) {
  string host4 = host;
  string host6 = host;
  if (host.empty()) {
    host4 = localhost_addr;
    host6 = localhost_addr_ipv6;
  }

  struct sockaddr_in addr4;
  bool ipv4_ok = get_address(AF_INET, host4, (struct sockaddr*)&addr4);
  struct sockaddr_in6 addr6;
  bool ipv6_ok = get_address(AF_INET6, host6, (struct sockaddr*)&addr6);

  int domain = -1;
  ScopedFd listen_fd;
  if (ipv4_ok) {
    listen_fd = ScopedFd(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (listen_fd.is_open()) {
      domain = AF_INET;
    }
  }
  if (!listen_fd.is_open() && ipv6_ok) {
    listen_fd = ScopedFd(socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (listen_fd.is_open()) {
      domain = AF_INET6;
    }
  }
  if (!listen_fd.is_open()) {
    FATAL() << "Couldn't create socket";
  }

  int reuseaddr = 1;
  int ret = setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr,
                       sizeof(reuseaddr));
  if (ret < 0) {
    FATAL() << "Couldn't set SO_REUSEADDR";
  }

  struct sockaddr* addr;
  size_t addr_size;
  in_port_t* addr_port;
  string* host_out;
  if (domain == AF_INET) {
    addr = (struct sockaddr*)&addr4;
    addr_size = sizeof(addr4);
    addr_port = &addr4.sin_port;
    addr4.sin_family = AF_INET;
    host_out = &host4;
  } else {
    addr = (struct sockaddr*)&addr6;
    addr_size = sizeof(addr6);
    addr_port = &addr6.sin6_port;
    addr6.sin6_family = AF_INET6;
    host_out = &host6;
  }

  do {
    *addr_port = htons(port);
    ret = ::bind(listen_fd, addr, addr_size);
    if (ret && probe == PROBE_PORT && (EADDRINUSE == errno || EACCES == errno || EINVAL == errno)) {
      port = 0;
      continue;
    }
    if (ret) {
      CLEAN_FATAL() << "Couldn't bind to port " << port;
    }

    ret = listen(listen_fd, 1 /*backlogged connection*/);
    if (ret && probe == PROBE_PORT && EADDRINUSE == errno) {
      port = 0;
      continue;
    }
    if (ret) {
      FATAL() << "Couldn't listen on port " << port;
    }
    if (port == 0) {
      socklen_t sa_size = addr_size;
      ret = getsockname(listen_fd, addr, &sa_size);
      if (ret) {
        FATAL() << "Could not get socket port";
      }

      port = ntohs(*addr_port);
    }
    break;
  } while (probe == PROBE_PORT);

  OpenedSocket result;
  result.fd = std::move(listen_fd);
  result.domain = domain;
  result.host = *host_out;
  result.port = port;
  return result;
}

void notifying_abort() {
  char* test_monitor_pid = getenv("RUNNING_UNDER_TEST_MONITOR");
  if (test_monitor_pid) {
    pid_t pid = atoi(test_monitor_pid);
    // Tell test-monitor to wake up and take a snapshot, and wait for it to
    // do so.
    kill(pid, SIGURG);
    sleep(10000);
  }

  abort();
}

void dump_rr_stack(ScopedFd& fd) {
  static const char msg[] = "=== Start rr backtrace:\n";
  write_all(fd, msg, sizeof(msg) - 1);
#ifdef EXECINFO_BACKTRACE
  void* buffer[1024];
  int count = backtrace(buffer, 1024);
  backtrace_symbols_fd(buffer, count, fd);
#else
  static const char msg_fallback[] = "<rr backtraces not available on this system>\n";
  write_all(fd, msg_fallback, sizeof(msg_fallback) - 1);
#endif
  static const char msg2[] = "=== End rr backtrace\n";
  write_all(fd, msg2, sizeof(msg2) - 1);
}

void check_for_leaks() {
  if (running_under_rr()) {
    // Don't do leak checking. The outer rr may have injected maps into our
    // address space that look like leaks to us.
    return;
  }
  for (KernelMapIterator it(getpid()); !it.at_end(); ++it) {
    auto km = it.current();
    if (km.fsname().find(Session::rr_mapping_prefix()) == 0) {
      FATAL() << "Leaked " << km;
    }
  }
}

void ensure_dir(const string& dir, const char* dir_type, mode_t mode) {
  if (dir.empty()) {
    FATAL() << "Empty directory name!";
  }
  size_t last_dir_component = dir.find_last_not_of('/');
  const string d = last_dir_component == string::npos
    ? "/" : dir.substr(0, last_dir_component + 1);
  struct stat st;
  if (0 > stat(d.c_str(), &st)) {
    if (errno != ENOENT) {
      FATAL() << "Error accessing " << dir_type << " " << dir << "'";
    }

    size_t last_slash = d.find_last_of('/');
    if (last_slash != string::npos) {
      ensure_dir(d.substr(0, max(last_slash, (size_t)1)), dir_type, mode);
    }

    // Allow for a race condition where someone else creates the directory
    if (0 > mkdir(d.c_str(), mode) && errno != EEXIST) {
      FATAL() << "Can't create " << dir_type << " `" << dir << "'";
    }
    if (0 > stat(d.c_str(), &st)) {
      FATAL() << "Can't stat " << dir_type << " `" << dir << "'";
    }
    return;
  }

  if (!(S_IFDIR & st.st_mode)) {
    FATAL() << "`" << dir << "' exists but isn't a directory.";
  }
  if (access(d.c_str(), W_OK)) {
    FATAL() << "Can't write to " << dir_type << " `" << dir << "'.";
  }
}

const char* tmp_dir() {
  const char* dir = getenv("RR_TMPDIR");
  if (dir) {
    ensure_dir(string(dir), "temporary file directory (RR_TMPDIR)", S_IRWXU);
    return dir;
  }
  dir = getenv("TMPDIR");
  if (dir) {
    ensure_dir(string(dir), "temporary file directory (TMPDIR)", S_IRWXU);
    return dir;
  }
  // Don't try to create "/tmp", that probably won't work well.
  if (access("/tmp", W_OK)) {
    FATAL() << "Can't write to temporary file directory /tmp.";
  }
  return "/tmp";
}

TempFile create_temporary_file(const char* pattern) {
  char buf[PATH_MAX];
  snprintf(buf, sizeof(buf) - 1, "%s/%s", tmp_dir(), pattern);
  buf[sizeof(buf) - 1] = 0;
  TempFile result;
  result.fd = ScopedFd(mkstemp(buf));
  result.name = buf;
  return result;
}

static ScopedFd create_memfd_file(const string &real_name) {
  ScopedFd fd(syscall(SYS_memfd_create, real_name.c_str(), 0));
  return fd;
}

static void replace_char(string& s, char c, char replacement) {
  size_t i = 0;
  while (string::npos != (i = s.find(c, i))) {
    s[i] = replacement;
  }
}

// Used only when memfd_create is not available, i.e. Linux < 3.17
static ScopedFd create_tmpfs_file(const string &real_name) {
  std::string name = real_name;
  replace_char(name, '/', '\\');
  name = string(tmp_dir()) + '/' + name;
  name = name.substr(0, 255);

  ScopedFd fd =
      ScopedFd(name.c_str(), O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0700);
  /* Remove the fs name so that we don't have to worry about
   * cleaning up this segment in error conditions. */
  unlink(name.c_str());
  return fd;
}

ScopedFd open_memory_file(const std::string &name)
{
  ScopedFd fd(create_memfd_file(name));
  if (!fd.is_open()) {
    fd = create_tmpfs_file(name);
  }
  return fd;
}

void good_random(void* out, size_t out_len) {
  ScopedFd fd("/dev/urandom", O_RDONLY);
  uint8_t* o = static_cast<uint8_t*>(out);
  if (fd.is_open()) {
    while (out_len > 0) {
      ssize_t ret = read(fd, o, out_len);
      if (ret <= 0) {
        break;
      }
      o += ret;
      out_len -= ret;
    }
  }
  for (size_t i = 0; i < out_len; ++i) {
    o[i] = random();
  }
}

vector<string> current_env() {
  vector<string> env;
  char** envp = environ;
  for (; *envp; ++envp) {
    env.push_back(*envp);
  }
  return env;
}

int get_num_cpus() {
  cpu_set_t affinity_mask;
  int ret = sched_getaffinity(0, sizeof(affinity_mask), &affinity_mask);
  if (ret < 0) {
    FATAL() << "sched_getaffinity failed";
  }
  return CPU_COUNT(&affinity_mask);
}

const uint8_t rdtsc_insn[2] = { 0x0f, 0x31 };

static const uint8_t rdtscp_insn[] = { 0x0f, 0x01, 0xf9 };
static const uint8_t cpuid_insn[] = { 0x0f, 0xa2 };
static const uint8_t int3_insn[] = { 0xcc };
static const uint8_t pushf_insn[] = { 0x9c };
static const uint8_t pushf16_insn[] = { 0x66, 0x9c };

// XXX this probably needs to be extended to decode ignored prefixes
TrappedInstruction trapped_instruction_at(Task* t, remote_code_ptr ip) {
  uint8_t insn[sizeof(rdtscp_insn)];
  ssize_t ret =
      t->read_bytes_fallible(ip.to_data_ptr<uint8_t>(), sizeof(insn), insn);
  if (ret < 0) {
    return TrappedInstruction::NONE;
  }
  size_t len = ret;
  if (len >= sizeof(rdtsc_insn) &&
      !memcmp(insn, rdtsc_insn, sizeof(rdtsc_insn))) {
    return TrappedInstruction::RDTSC;
  }
  if (len >= sizeof(rdtscp_insn) &&
      !memcmp(insn, rdtscp_insn, sizeof(rdtscp_insn))) {
    return TrappedInstruction::RDTSCP;
  }
  if (len >= sizeof(cpuid_insn) &&
      !memcmp(insn, cpuid_insn, sizeof(cpuid_insn))) {
    return TrappedInstruction::CPUID;
  }
  if (len >= sizeof(int3_insn) &&
      !memcmp(insn, int3_insn, sizeof(int3_insn))) {
    return TrappedInstruction::INT3;
  }
  if (len >= sizeof(pushf_insn) &&
      !memcmp(insn, pushf_insn, sizeof(pushf_insn))) {
    return TrappedInstruction::PUSHF;
  }
  if (len >= sizeof(pushf16_insn) &&
      !memcmp(insn, pushf16_insn, sizeof(pushf16_insn))) {
    return TrappedInstruction::PUSHF16;
  }
  return TrappedInstruction::NONE;
}

size_t trapped_instruction_len(TrappedInstruction insn) {
  if (insn == TrappedInstruction::RDTSC) {
    return sizeof(rdtsc_insn);
  } else if (insn == TrappedInstruction::RDTSCP) {
    return sizeof(rdtscp_insn);
  } else if (insn == TrappedInstruction::CPUID) {
    return sizeof(cpuid_insn);
  } else if (insn == TrappedInstruction::INT3) {
    return sizeof(int3_insn);
  } else if (insn == TrappedInstruction::PUSHF) {
    return sizeof(pushf_insn);
  } else if (insn == TrappedInstruction::PUSHF16) {
    return sizeof(pushf16_insn);
  } else {
    return 0;
  }
}

/**
 * Certain instructions generate deterministic signals but also advance pc.
 * Look *backwards* and see if this was one of them.
 */
bool is_advanced_pc_and_signaled_instruction(Task* t, remote_code_ptr ip) {
#if defined(__i386__) || defined(__x86_64__)
  uint8_t insn[sizeof(int3_insn)];
  ssize_t ret =
      t->read_bytes_fallible(ip.to_data_ptr<uint8_t>() - sizeof(insn), sizeof(insn), insn);
  if (ret < 0) {
    return false;
  }
  size_t len = ret;
  if (len >= sizeof(int3_insn) &&
      !memcmp(insn, int3_insn, sizeof(int3_insn))) {
    return true;
  }
#else
  UNUSED(t);
  UNUSED(ip);
#endif
  return false;
}

string get_cpu_lock_file() {
  const char* lock_file = getenv("_RR_CPU_LOCK_FILE");
  return lock_file ? lock_file : trace_save_dir() + "/cpu_lock";
}

/**
 * Pick a CPU at random to bind to, unless --cpu-unbound has been given,
 * in which case we return -1.
 */
int choose_cpu(BindCPU bind_cpu, ScopedFd &cpu_lock_fd_out) {
  if (bind_cpu == UNBOUND_CPU) {
    return -1;
  }

  // Find out which CPUs we're allowed to run on at all.
  // sched_getaffinity intersects the task's `cpu_mask`
  // (/proc/.../status Cpus_allowed_list) with `cpu_active_mask`
  // which is almost the same as /sys/devices/system/cpu/online
  cpu_set_t affinity_mask;
  int ret = sched_getaffinity(0, sizeof(affinity_mask), &affinity_mask);
  if (ret < 0) {
    FATAL() << "sched_getaffinity failed";
  }
  std::vector<int> cpus;
  for (int i = 0; i < CPU_SETSIZE; ++i) {
    if (CPU_ISSET(i, &affinity_mask) && PerfCounters::support_cpu(i)) {
      cpus.push_back(i);
    }
  }
  if (cpus.empty()) {
    FATAL() << "Can't find a valid CPU to run on";
  }

  // When many copies of rr are running on the same machine, it's easy for them
  // to oversubscribe a CPU. To avoid this situation, we have a lock file, where
  // each running rr process will lock the n-th byte if it is running on that
  // particular CPU. That way subsequent rr processes can avoid in-use cores
  // if possible.
  string cpu_lock_file = get_cpu_lock_file();
  cpu_lock_fd_out = ScopedFd(cpu_lock_file.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC, 0600);

  // Make sure the locks file is big enough
  if (cpu_lock_fd_out.is_open()) {
    struct stat stat;
    int err = fstat(cpu_lock_fd_out, &stat);
    DEBUG_ASSERT(err == 0);
    int configured_cpus = (int)sysconf(_SC_NPROCESSORS_CONF);
    if (stat.st_size < configured_cpus) {
      if (ftruncate(cpu_lock_fd_out, configured_cpus)) {
        FATAL() << "Failed to resize locks file";
      }
    }
  }

  // Pin tracee tasks to a random logical CPU, both in
  // recording and replay.  Tracees can see which HW
  // thread they're running on by asking CPUID, and we
  // don't have a way to emulate it yet.  So if a tracee
  // happens to be scheduled on a different core in
  // recording than replay, it can diverge.  (And
  // indeed, has been observed to diverge in practice,
  // in glibc.)
  //
  // Note that we will pin both the tracee processes *and*
  // the tracer process.  This ends up being a tidy
  // performance win in certain circumstances,
  // presumably due to cheaper context switching and/or
  // better interaction with CPU frequency scaling.
  if (bind_cpu >= 0) {
    if (cpu_lock_fd_out.is_open()) {
      struct flock lock {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = bind_cpu,
        .l_len = 1,
        .l_pid = 0
      };
      // Try to acquire the lock for this CPU
      (void)fcntl(cpu_lock_fd_out, F_SETLK, &lock);
      // Ignore fcntl errors - nothing we can do
    }
    return bind_cpu;
  }

  if (cpu_lock_fd_out.is_open()) {
    // Try twice to allocate a CPU. If we fail twice, pick a random one
    for (int i = 0; i < 2; ++i) {
      std::shuffle (cpus.begin(), cpus.end(), std::default_random_engine(random()));
      for (int cpu : cpus) {
        struct flock lock {
          .l_type = F_WRLCK,
          .l_whence = SEEK_SET,
          .l_start = cpu,
          .l_len = 1,
          .l_pid = 0
        };
        // Try to acquire the lock for this CPU
        int err = fcntl(cpu_lock_fd_out, F_SETLK, &lock);
        if (err == 0) {
          return cpu;
        }
        else if (err == -1) {
          if (errno != EACCES && errno != EAGAIN) {
            FATAL() << "Unexpected error trying to acquire CPU lock";
          }
        }
      }
    }
  }

  // Didn't work - just use a random CPU
  cpu_lock_fd_out.close();
  return cpus[random() % cpus.size()];
}

uint32_t crc32(uint32_t crc, unsigned char* buf, size_t len) {
  static const uint32_t crc32_table[256] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
    0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
    0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
    0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
    0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
    0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
    0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
    0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
    0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
  };

  for (unsigned char* end = buf + len; buf < end; ++buf) {
    crc = crc32_table[(crc ^ *buf) & 0xff] ^ (crc >> 8);
  }
  return crc;
}

void write_all(int fd, const void* buf, size_t size) {
  while (size > 0) {
    ssize_t ret = ::write(fd, buf, size);
    if (ret <= 0) {
      FATAL() << "Can't write " << size << " bytes";
    }
    buf = static_cast<const char*>(buf) + ret;
    size -= ret;
  }
}

ssize_t pwrite_all_fallible(int fd, const void* buf, size_t size, off64_t offset) {
  ssize_t written = 0;
  while (size > 0) {
    ssize_t ret = ::pwrite64(fd, buf, size, offset);
    if (ret <= 0) {
      if (written > 0) {
        return written;
      }
      return ret;
    }
    buf = static_cast<const char*>(buf) + ret;
    written += ret;
    offset += ret;
    size -= ret;
  }
  return written;
}

bool is_directory(const char* path) {
  struct stat buf;
  if (stat(path, &buf) < 0) {
    return false;
  }
  return (buf.st_mode & S_IFDIR) != 0;
}

const char* filename(const char* path) {
  const char* dir = strrchr(path, '/');
  return dir ? ++dir : path;
}

bool is_trace(const string& trace) {
  string ver = trace + "/version";
  string inc = trace + "/incomplete";
  return access(ver.c_str(), F_OK) == 0 || access(inc.c_str(), F_OK) == 0;
}

bool is_latest_trace(const string& trace) {
  string latest = latest_trace_symlink();
  if (access(latest.c_str(), F_OK) != 0) {
    return false;
  }
  latest = real_path(latest);
  return latest == trace; 
}

bool remove_latest_trace_symlink() {
  const string latest = latest_trace_symlink();
  int ret = remove(latest.c_str());
  if (ret) {
    perror(latest.c_str());
    fprintf(stderr,
            "\n"
            "rr: Failed to remove latest_trace symlink: error code %d\n"
            "\n",
            ret);
    return false;
  }
  return true;
}

bool is_valid_trace_name(const string& entry, std::string* reason) {
  // filename corresponds to dirname
  const string name = filename(entry.c_str());

  if (name.empty()) {
    if (reason) {
      *reason = "Empty";
    }
    return false;
  }
  if (name[0] == '.' || name[0] == '#') {
    if (reason) {
      *reason = "Cannot start with . or #";
    }
    return false;
  }
  if (name[name.length() - 1] == '~') {
    if (reason) {
      *reason = "Cannot end with ~";
    }
    return false;
  }
  if (name == "cpu_lock") {
    if (reason) {
      *reason = "Name cpu_lock is reserved";
    }
    return false;
  }

  return true;
}

ssize_t read_to_end(const ScopedFd& fd, size_t offset, void* buf, size_t size) {
  ssize_t ret = 0;
  while (size) {
    ssize_t r = pread(fd.get(), buf, size, offset);
    if (r < 0) {
      return -1;
    }
    if (r == 0) {
      return ret;
    }
    offset += r;
    ret += r;
    size -= r;
    buf = static_cast<uint8_t*>(buf) + r;
  }
  return ret;
}

static struct rlimit raise_resource_limit(int resource, rlim_t max_value) {
  struct rlimit initial;

  if (getrlimit(resource, &initial) < 0) {
    FATAL() << "Can't get rlimit " << rlimit_resource_name(resource);
  }

  struct rlimit new_limit = initial;
  new_limit.rlim_cur = max<rlim_t>(new_limit.rlim_cur, max_value);
  if (new_limit.rlim_max != RLIM_INFINITY) {
    new_limit.rlim_cur = min<rlim_t>(new_limit.rlim_cur, new_limit.rlim_max);
  }
  if (new_limit.rlim_cur != initial.rlim_cur) {
    if (setrlimit(resource, &new_limit) < 0) {
      LOG(warn) << "Failed to raise rlimit " << rlimit_resource_name(resource)
          << " to " << new_limit.rlim_cur;
    }
  }

  return initial;
}

static void restore_resource_limit(int resource, const struct rlimit& old_limit) {
  if (setrlimit(resource, &old_limit) < 0) {
    LOG(warn) << "Failed to reset rlimit " << rlimit_resource_name(resource);
  }
}

static const int MAX_TRACEE_TASKS = 65536;
static struct rlimit initial_fd_limit;
static struct rlimit initial_memlock_limit;

void raise_resource_limits() {
  // We need up to 7 perf event counters per tracee task
  initial_fd_limit = raise_resource_limit(RLIMIT_NOFILE, 1024 + 7 * MAX_TRACEE_TASKS);
  // We may need one page of locked memory per tracee task
  initial_memlock_limit = raise_resource_limit(RLIMIT_MEMLOCK, page_size() * 1 * MAX_TRACEE_TASKS);
}

void restore_initial_resource_limits() {
  restore_resource_limit(RLIMIT_NOFILE, initial_fd_limit);
  restore_resource_limit(RLIMIT_MEMLOCK, initial_memlock_limit);
}

template <typename Arch> static size_t word_size_arch() {
  return sizeof(typename Arch::signed_long);
}

size_t word_size(SupportedArch arch) {
  RR_ARCH_FUNCTION(word_size_arch, arch);
}

string json_escape(const string& str, size_t pos) {
  string out;
  for (size_t i = pos; i < str.size(); ++i) {
    unsigned char c = str[i];
    if (c < 32) {
      char buf[8];
      sprintf(buf, "\\u%04x", c);
      out += buf;
    } else if (c == '\\') {
      out += "\\\\";
    } else if (c == '\"') {
      out += "\\\"";
    } else {
      out += c;
    }
  }
  return out;
}

void sleep_time(double t) {
  struct timespec ts;
  ts.tv_sec = (time_t)floor(t);
  ts.tv_nsec = (long)((t - ts.tv_sec) * 1e9);
  nanosleep(&ts, NULL);
}

static bool is_component(const char* p, const char* component) {
  while (*component) {
    if (*p != *component) {
      return false;
    }
    ++p;
    ++component;
  }
  return *p == '/' || !*p;
}

void normalize_file_name(string& s)
{
  size_t s_len = s.size();
  size_t out = 0;
  for (size_t i = 0; i < s_len; ++i) {
    if (s[i] == '/') {
      if (s.c_str()[i + 1] == '/') {
        // Skip redundant '/'
        continue;
      }
      if (is_component(s.c_str() + i + 1, ".")) {
        // Skip redundant '/.'
        ++i;
        continue;
      }
      if (is_component(s.c_str() + i + 1, "..")) {
        // Peel off '/..'
        if (out == 0) {
          // If there's nothing to peel off, just discard this.
          i += 2;
          continue;
        }
        size_t p = s.rfind('/', out - 1);
        if (p != string::npos) {
          out = p;
          i += 2;
          continue;
        }
      }
    }
    s[out] = s[i];
    ++out;
  }
  s.resize(out);
}

std::vector<int> read_all_proc_fds(pid_t tid)
{
  std::vector<int> ret;
  char buf[1000];
  sprintf(buf, "/proc/%d/fd", tid);
  DIR *fddir = opendir(buf);
  DEBUG_ASSERT(fddir != nullptr);
  while (struct dirent *dir = readdir(fddir)) {
    ret.push_back(atoi(dir->d_name));
  }
  closedir(fddir);
  return ret;
}

std::string find_exec_stub(SupportedArch arch) {
  string exe_path = resource_path() + "bin/";
  if (arch == x86 && NativeArch::arch() == x86_64) {
    exe_path += "rr_exec_stub_32";
  } else {
    exe_path += "rr_exec_stub";
  }
  return exe_path;
}

int pop_count(uint64_t v) {
  int ret = 0;
  while (v > 0) {
    if (v & 1) {
      ++ret;
    }
    v >>= 1;
  }
  return ret;
}

void SAFE_FATAL(int err, const char *msg)
{
  static char prefix[] = "FATAL (errno = ";
  const char *errstr = errno_name_cstr(err);
  char buf[100];
  if (errstr == NULL) {
    snprintf(buf, sizeof(buf), "errno(%d)", err);
    errstr = buf;
  }
  static char bridge[] = "): ";
  static char nl[] = "\n";
  struct iovec out[5] = {
    {.iov_base = prefix, .iov_len=sizeof(prefix)},
    {.iov_base = (char*)errstr, .iov_len=strlen(errstr)},
    {.iov_base = bridge, .iov_len=sizeof(errstr)},
    {.iov_base = (char*)msg, .iov_len=strlen(msg)},
    {.iov_base = nl, .iov_len=sizeof(nl)}
  };
  __attribute__((unused)) ssize_t ret = ::writev(STDERR_FILENO, out, sizeof(out)/sizeof(struct iovec));
  abort();
}

static int child_SIGSEGV(__attribute__((unused)) void* arg) {
  kill(getpid(), SIGSEGV);
  return 0;
}

#ifdef __SANITIZE_ADDRESS__
#include <sanitizer/lsan_interface.h>
static int rr_lsan_is_turned_off;
int __lsan_is_turned_off(void)
{
  return rr_lsan_is_turned_off;
}
#include <sanitizer/asan_interface.h>
const char *__asan_default_options() {
  return "verify_asan_link_order=0";
}
#endif

bool coredumping_signal_takes_down_entire_vm() {
  // The kernel behavior here changed in 5.16. Prior to that,
  // a coredumping signal would bring down the entire vm.
  // Starting with 5.16 it only brings down the thread group.
  // -1 here indicates uninitialized, 0 the new behavior, and
  // 1 the old behavior.
  static int coredumping_signal_vm_behavior = -1;
  if (coredumping_signal_vm_behavior < 0) {
    pid_t child;
    LOG(debug) << "Testing coredumping behavior in the presence of CLONE_VM";
    if ((child = fork()) == 0) {
      // Remove any handlers and make sure we get the default signal behavior.
      signal(SIGSEGV, SIG_DFL);
      // Don't litter the system with core dumps.
      prctl(PR_SET_DUMPABLE, 0);
#ifdef __SANITIZE_ADDRESS__
      rr_lsan_is_turned_off = 1;
#endif
      // Allocate a stack for the child.
      const size_t stack_size = 1 << 20;
      void* stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

      pid_t tid = clone(child_SIGSEGV, (void*)((uintptr_t)stack + stack_size),
                      CLONE_VM, NULL, NULL, NULL, NULL);
      DEBUG_ASSERT(tid > 0);

      WaitResult result = WaitManager::wait_exit(WaitOptions(tid));
      DEBUG_ASSERT(result.code == WAIT_OK);
      DEBUG_ASSERT(result.status.type() == WaitStatus::FATAL_SIGNAL);
      exit(0);
    }

    DEBUG_ASSERT(child > 0);
    WaitResult result = WaitManager::wait_exit(WaitOptions(child));
    DEBUG_ASSERT(result.code == WAIT_OK);
    coredumping_signal_vm_behavior = result.status.type() == WaitStatus::FATAL_SIGNAL;
  }

  return coredumping_signal_vm_behavior > 0;
}

int parse_tid_from_proc_path(const std::string& pathname,
                             const std::string& property) {
  // XXX When rr becomes c++17 - use string view instead. Has better API for
  // this stuff.
  const auto proc_length = 6;
  const auto prop_should_begin =
      pathname.size() - property.size() - (pathname.back() == '/');
  if (pathname.substr(prop_should_begin, property.size()) == property) {
    const auto task = "task/"s;
    const auto pos = pathname.find(task);
    if (pos == std::string::npos) {
      auto s = pathname.substr(proc_length);
      if (pathname.back() == '/')
        s.pop_back();
      char* end;
      const int tid = strtol(s.c_str(), &end, 10);
      if (end == property) {
        return tid;
      }
    } else {
      auto s = pathname.substr(pos + task.size());
      if (pathname.back() == '/')
        s.pop_back();
      char* end;
      const int tid = strtol(s.c_str(), &end, 10);
      if (end == property) {
        return tid;
      }
    }
  }
  return -1;
}

void replace_in_buffer(MemoryRange src, const uint8_t* src_data,
                       MemoryRange dst, uint8_t* dst_data) {
  remote_ptr<void> overlap_start = max(src.start(), dst.start());
  remote_ptr<void> overlap_end = min(src.end(), dst.end());
  if (overlap_start < overlap_end) {
    memcpy(dst_data + (overlap_start - dst.start()),
           src_data + (overlap_start - src.start()),
           overlap_end - overlap_start);
  }
}

void base_name(string& s) {
  size_t p = s.rfind('/');
  if (p != string::npos) {
    s.erase(0, p + 1);
  }
}

static optional<int> init_read_perf_event_paranoid() {
  ScopedFd fd("/proc/sys/kernel/perf_event_paranoid", O_RDONLY);
  if (fd.is_open()) {
    char buf[100];
    ssize_t size = read(fd, buf, sizeof(buf) - 1);
    if (size >= 0) {
      buf[size] = 0;
      return atoi(buf);
    }
  }

  return nullopt;
}

optional<int> read_perf_event_paranoid() {
  static optional<int> value = init_read_perf_event_paranoid();
  return value;
}

} // namespace rr
