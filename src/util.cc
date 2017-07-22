/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define FIRST_INTERESTING_EVENT 10700
//#define LAST_INTERESTING_EVENT 10900

#include "util.h"

#include <arpa/inet.h>
#include <assert.h>
#include <elf.h>
#include <execinfo.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/capability.h>
#include <linux/magic.h>
#include <linux/prctl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <algorithm>
#include <fstream>
#include <string>

#include "preload/preload_interface.h"

#include "AddressSpace.h"
#include "AutoRemoteSyscalls.h"
#include "Flags.h"
#include "PerfCounters.h"
#include "ReplaySession.h"
#include "ReplayTask.h"
#include "TraceStream.h"
#include "kernel_abi.h"
#include "kernel_metadata.h"
#include "log.h"
#include "seccomp-bpf.h"
void good_random(uint8_t* out, size_t out_len);

using namespace std;

namespace rr {

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
  flags |= (CLONE_THREAD & flags_arg) ? CLONE_SHARE_TASK_GROUP : 0;
  flags |= (CLONE_VM & flags_arg) ? CLONE_SHARE_VM : 0;
  flags |= (CLONE_FILES & flags_arg) ? CLONE_SHARE_FILES : 0;
  return flags;
}

size_t page_size() { return sysconf(_SC_PAGE_SIZE); }

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

void format_dump_filename(Task* t, TraceFrame::Time global_time,
                          const char* tag, char* filename,
                          size_t filename_size) {
  snprintf(filename, filename_size - 1, "%s/%d_%d_%s", t->trace_dir().c_str(),
           t->rec_tid, global_time, tag);
}

bool should_dump_memory(const TraceFrame& f) {
  const Flags* flags = &Flags::get();

#if defined(FIRST_INTERESTING_EVENT)
  int is_syscall_exit = event >= 0 && state == STATE_SYSCALL_EXIT;
  if (is_syscall_exit && RECORD == Flags->option &&
      FIRST_INTERESTING_EVENT <= global_time &&
      global_time <= LAST_INTERESTING_EVENT) {
    return true;
  }
  if (global_time > LAST_INTERESTING_EVENT) {
    return false;
  }
#endif
  return flags->dump_on == Flags::DUMP_ON_ALL ||
         (f.event().is_syscall_event() &&
          f.event().Syscall().number == flags->dump_on) ||
         (f.event().is_signal_event() &&
          f.event().Signal().siginfo.si_signo == -flags->dump_on) ||
         (flags->dump_on == Flags::DUMP_ON_RDTSC &&
          f.event().type() == EV_SEGV_DISABLED_INSN) ||
         flags->dump_at == int(f.time());
}

void dump_process_memory(Task* t, TraceFrame::Time global_time,
                         const char* tag) {
  char filename[PATH_MAX];
  FILE* dump_file;

  format_dump_filename(t, global_time, tag, filename, sizeof(filename));
  dump_file = fopen64(filename, "w");

  const AddressSpace& as = *(t->vm());
  for (auto m : as.maps()) {
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

static void notify_checksum_error(ReplayTask* t, TraceFrame::Time global_time,
                                  unsigned checksum, unsigned rec_checksum,
                                  const string& raw_map_line) {
  char cur_dump[PATH_MAX];
  char rec_dump[PATH_MAX];

  dump_process_memory(t, global_time, "checksum_error");

  /* TODO: if the right recorder memory dump is present,
   * automatically compare them, taking the oddball
   * not-mapped-during-replay region(s) into account.  And if
   * not present, tell the user how to make one in a future
   * run. */
  format_dump_filename(t, global_time, "checksum_error", cur_dump,
                       sizeof(cur_dump));
  format_dump_filename(t, global_time, "rec", rec_dump, sizeof(rec_dump));

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

/**
 * This helper does the heavy lifting of storing or validating
 * checksums.  The iterator data determines which behavior the helper
 * function takes on, and to/from which file it writes/read.
 */
enum ChecksumMode { STORE_CHECKSUMS, VALIDATE_CHECKSUMS };
struct checksum_iterator_data {
  ChecksumMode mode;
  FILE* checksums_file;
  TraceFrame::Time global_time;
};

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
      (should_copy_mmap_region(m.map, st) || (PROT_WRITE & m.map.prot()));
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

/**
 * Either create and store checksums for each segment mapped in |t|'s
 * address space, or validate an existing computed checksum.  Behavior
 * is selected by |mode|.
 */
static void iterate_checksums(Task* t, ChecksumMode mode,
                              TraceFrame::Time global_time) {
  struct checksum_iterator_data c;
  memset(&c, 0, sizeof(c));
  char filename[PATH_MAX];
  const char* fmode = (STORE_CHECKSUMS == mode) ? "w" : "r";

  c.mode = mode;
  snprintf(filename, sizeof(filename) - 1, "%s/%d_%d", t->trace_dir().c_str(),
           global_time, t->rec_tid);
  c.checksums_file = fopen64(filename, fmode);
  c.global_time = global_time;
  if (!c.checksums_file) {
    FATAL() << "Failed to open checksum file " << filename;
  }

  remote_ptr<unsigned char> in_replay_flag;
  unsigned char in_replay = 0;
  if (t->preload_globals) {
    in_replay_flag = REMOTE_PTR_FIELD(t->preload_globals, in_replay);
    in_replay = t->read_mem(in_replay_flag);
    t->write_mem(in_replay_flag, (unsigned char)0);
  }

  const AddressSpace& as = *t->vm();
  for (auto it = as.maps().begin(); it != as.maps().end(); ++it) {
    auto m = *it;
    string raw_map_line = m.map.str();
    uint32_t rec_checksum = 0;

    if (VALIDATE_CHECKSUMS == mode) {
      char line[1024];
      fgets(line, sizeof(line), c.checksums_file);
      unsigned long rec_start;
      unsigned long rec_end;
      unsigned tmp_checksum;
      int nparsed =
          sscanf(line, "(%x) %lx-%lx", &tmp_checksum, &rec_start, &rec_end);
      rec_checksum = tmp_checksum;
      remote_ptr<void> rec_start_addr = rec_start;
      remote_ptr<void> rec_end_addr = rec_end;
      ASSERT(t, 3 == nparsed) << "Parsed " << nparsed << " items";
      // If we have artifical SIGBUS regions, those may (if the entire region
      // was SIGBUS), but need not have existed during recording, so fast
      // forward to the next real region.
      while (m.map.start() != rec_start_addr) {
        ASSERT(t, m.flags & AddressSpace::Mapping::IS_SIGBUS_REGION)
            << "Segment " << rec_start_addr << "-" << rec_end_addr
            << " changed to " << m.map << "??";
        ASSERT(t, it != as.maps().end());
        m = *(++it);
        continue;
      }
      // If the backing file is too short, we cut mappings short, to make sure
      // have the same behavior as during recording. Tolerate this.
      ASSERT(t, m.map.end() <= rec_end_addr) << "Segment " << rec_start_addr
                                             << "-" << rec_end_addr
                                             << " changed to " << m.map << "??";
      if (is_start_of_scratch_region(t, rec_start_addr)) {
        /* Replay doesn't touch scratch regions, so
         * their contents are allowed to diverge.
         * Tracees can't observe those segments unless
         * they do something sneaky (or disastrously
         * buggy). */
        LOG(debug) << "Not validating scratch starting at " << rec_start_addr;
        continue;
      }
      if (rec_checksum == ignored_checksum) {
        LOG(debug) << "Checksum not computed during recording";
        continue;
      } else if (rec_checksum == sigbus_checksum) {
        // This was a SIGBUS equivalent region. During replay, this is either
        // an explicit SIGBUS region, indicated by the IS_SIGBUS_REGION flag
        // if the data came from the trace, or an implicit one (which we will
        // catch below) if the data came from a cloned file.
        if (m.flags & AddressSpace::Mapping::IS_SIGBUS_REGION) {
          continue;
        }
      }
    } else {
      if (!checksum_segment_filter(m)) {
        fprintf(c.checksums_file, "(%x) %s\n", ignored_checksum,
                raw_map_line.c_str());
        continue;
      }
    }

    vector<uint8_t> mem;
    mem.resize(m.map.size());
    ssize_t valid_mem_len =
        t->read_bytes_fallible(m.map.start(), m.map.size(), mem.data());
    if (valid_mem_len < 0) {
      /* It is possible for whole mappings to be beyond the extent of the
       * backing file, in which case read_bytes_fallible will return -1.
       * During replay this will be a SIGBUS region (or, if the file was cloned,
       * we will end up here again), so skip it now.
       */
      ASSERT(t, valid_mem_len == -1 && errno == EIO);
      if (VALIDATE_CHECKSUMS == mode) {
        ASSERT(t, rec_checksum == sigbus_checksum);
      } else {
        fprintf(c.checksums_file, "(%x) %s\n", sigbus_checksum,
                raw_map_line.c_str());
      }
      continue;
    }
    mem.resize(valid_mem_len);

    if (m.flags & AddressSpace::Mapping::IS_SYSCALLBUF) {
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
      * So here, we set things up so that we only checksum
      * the deterministic region. */
      auto child_hdr = m.map.start().cast<struct syscallbuf_hdr>();
      auto hdr = t->read_mem(child_hdr);
      mem.resize(sizeof(hdr) + hdr.num_rec_bytes +
                 sizeof(struct syscallbuf_record));
    }

    uint32_t checksum = compute_checksum(mem.data(), mem.size());

    if (STORE_CHECKSUMS == mode) {
      fprintf(c.checksums_file, "(%x) %s\n", checksum, raw_map_line.c_str());
    } else {
      ASSERT(t, t->session().is_replaying());
      auto rt = static_cast<ReplayTask*>(t);

      // Ignore checksums when valid_mem_len == 0
      if (checksum != rec_checksum) {
        notify_checksum_error(rt, c.global_time, checksum, rec_checksum,
                              raw_map_line.c_str());
      }
    }
  }

  if (in_replay_flag) {
    t->write_mem(in_replay_flag, in_replay);
  }

  fclose(c.checksums_file);
}

bool should_checksum(const TraceFrame& f) {
  if (f.event().type() == EV_EXIT || f.event().type() == EV_UNSTABLE_EXIT) {
    // Task is dead, or at least detached, and we can't read its memory safely.
    return false;
  }
  if (f.event().has_ticks_slop()) {
    // We may not be at the same point during recording and replay, so don't
    // compute checksums.
    return false;
  }

  int checksum = Flags::get().checksum;
  bool is_syscall_exit = EV_SYSCALL == f.event().type() &&
                         EXITING_SYSCALL == f.event().Syscall().state;

#if defined(FIRST_INTERESTING_EVENT)
  if (is_syscall_exit && FIRST_INTERESTING_EVENT <= global_time &&
      global_time <= LAST_INTERESTING_EVENT) {
    return true;
  }
  if (global_time > LAST_INTERESTING_EVENT) {
    return false;
  }
#endif
  if (Flags::CHECKSUM_NONE == checksum) {
    return false;
  }
  if (Flags::CHECKSUM_ALL == checksum) {
    return true;
  }
  if (Flags::CHECKSUM_SYSCALL == checksum) {
    return is_syscall_exit;
  }
  /* |checksum| is a global time point. */
  return checksum <= int(f.time());
}

void checksum_process_memory(Task* t, TraceFrame::Time global_time) {
  iterate_checksums(t, STORE_CHECKSUMS, global_time);
}

void validate_process_memory(Task* t, TraceFrame::Time global_time) {
  iterate_checksums(t, VALIDATE_CHECKSUMS, global_time);
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

static bool has_fs_name(const string& path) {
  struct stat dummy;
  return 0 == stat(path.c_str(), &dummy);
}

static bool is_tmp_file(const string& path) {
  if (getenv("RR_TRUST_TEMP_FILES")) {
    return false;
  }
  struct statfs sfs;
  statfs(path.c_str(), &sfs);
  return (TMPFS_MAGIC == sfs.f_type
          // In observed configurations of Ubuntu 13.10, /tmp is
          // a folder in the / fs, not a separate tmpfs.
          || path.c_str() == strstr(path.c_str(), "/tmp/"));
}

bool should_copy_mmap_region(const KernelMapping& mapping,
                             const struct stat& stat) {
  if (getenv("RR_COPY_ALL_FILES")) {
    return true;
  }

  int flags = mapping.flags();
  int prot = mapping.prot();
  const string& file_name = mapping.fsname();
  bool private_mapping = (flags & MAP_PRIVATE);

  // TODO: handle mmap'd files that are unlinked during
  // recording.
  if (!has_fs_name(file_name)) {
    LOG(debug) << "  copying unlinked file";
    return true;
  }
  if (is_tmp_file(file_name)) {
    LOG(debug) << "  copying file on tmpfs";
    return true;
  }
  if (file_name == "/etc/ld.so.cache") {
    // This file changes on almost every system update so we should copy it.
    LOG(debug) << "  copying " << file_name;
    return true;
  }
  if (private_mapping && (prot & PROT_EXEC)) {
    /* Be optimistic about private executable mappings */
    LOG(debug) << "  (no copy for +x private mapping " << file_name << ")";
    return false;
  }
  if (private_mapping && (0111 & stat.st_mode)) {
    /* A private mapping of an executable file usually
     * indicates mapping data sections of object files.
     * Since we're already assuming those change very
     * infrequently, we can avoid copying the data
     * sections too. */
    LOG(debug) << "  (no copy for private mapping of +x " << file_name << ")";
    return false;
  }
  bool can_read_file = (0 == access(file_name.c_str(), R_OK));
  if (!can_read_file) {
    // It's possible for a tracee to mmap a file it doesn't have permission
    // to read, e.g. if a daemon opened the file and passed the fd over a
    // socket. We should copy the data now because we won't be able to read
    // it later. nscd does this.
    return true;
  }

  // TODO: using "can the euid of the rr process write this
  // file" as an approximation of whether the tracee can write
  // the file.  If the tracee is messing around with
  // set*[gu]id(), the real answer may be different.
  bool can_write_file = (0 == access(file_name.c_str(), W_OK));

  // Inside a user namespace, the real root user may be mapped to UID 65534.
  if (!can_write_file && (0 == stat.st_uid || 65534 == stat.st_uid)) {
    // We would like to assert this, but on Ubuntu 13.10,
    // the file /lib/i386-linux-gnu/libdl-2.17.so is
    // writeable by root for unknown reasons.
    // assert(!(prot & PROT_WRITE));
    /* Mapping a file owned by root: we don't care if this
     * was a PRIVATE or SHARED mapping, because unless the
     * program is disastrously buggy or unlucky, the
     * mapping is effectively PRIVATE.  Bad luck can come
     * from this program running during a system update,
     * or a user being added, which is probably less
     * frequent than even system updates.
     *
     * XXX what about the fontconfig cache files? */
    LOG(debug) << "  (no copy for root-owned " << file_name << ")";
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
    FATAL() << "Unhandled mmap " << file_name << "(prot:" << HEX(prot)
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

CPUIDData cpuid(uint32_t code, uint32_t subrequest) {
  CPUIDData result;
  asm volatile("cpuid"
               : "=a"(result.eax), "=b"(result.ebx), "=c"(result.ecx),
                 "=d"(result.edx)
               : "a"(code), "c"(subrequest));
  return result;
}

#define SEGV_HANDLER_MAGIC 0x98765432

static void cpuid_segv_handler(__attribute__((unused)) int sig,
                               __attribute__((unused)) siginfo_t* si,
                               void* user) {
  ucontext_t* ctx = (ucontext_t*)user;
#if defined(__i386__)
  ctx->uc_mcontext.gregs[REG_EIP] += 2;
  ctx->uc_mcontext.gregs[REG_EAX] = SEGV_HANDLER_MAGIC;
#elif defined(__x86_64__)
  ctx->uc_mcontext.gregs[REG_RIP] += 2;
  ctx->uc_mcontext.gregs[REG_RAX] = SEGV_HANDLER_MAGIC;
#else
#error unknown architecture
#endif
}

static CPUIDRecord cpuid_record(uint32_t eax, uint32_t ecx) {
  CPUIDRecord result = { eax, ecx, cpuid(eax, ecx) };
  return result;
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

  CPUIDRecord extended_info = cpuid_record(CPUID_INTELEXTENDED, UINT32_MAX);
  results.push_back(extended_info);
  int extended_info_max = min(up_to, extended_info.out.eax);
  for (int extended = CPUID_INTELEXTENDED + 1; extended <= extended_info_max;
       ++extended) {
    results.push_back(cpuid_record(extended, UINT32_MAX));
  }

  return results;
}

vector<CPUIDRecord> all_cpuid_records() {
  return gather_cpuid_records(UINT32_MAX);
}

bool cpuid_faulting_works() {
  static bool did_check_cpuid_faulting = false;
  static bool cpuid_faulting_ok = false;

  if (did_check_cpuid_faulting) {
    return cpuid_faulting_ok;
  }
  did_check_cpuid_faulting = true;

  // Test to see if CPUID faulting works.
  if (syscall(SYS_arch_prctl, ARCH_SET_CPUID, 0) != 0) {
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
  if (syscall(SYS_arch_prctl, ARCH_SET_CPUID, 1) < 0) {
    FATAL() << "Can't restore ARCH_SET_CPUID";
  }
  return cpuid_faulting_ok;
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
  int flags = (int)regs.arg1();
  // If these flags aren't set, the corresponding clone parameters may be
  // invalid pointers, so make sure they're ignored.
  if (!(flags & CLONE_PARENT_SETTID)) {
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
static TraceFrame::Time instruction_trace_at_event_start = 0;
static TraceFrame::Time instruction_trace_at_event_last = 0;

bool trace_instructions_up_to_event(TraceFrame::Time event) {
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

string exe_directory() {
  static string exe_path = read_exe_dir();
  return exe_path;
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

bool running_under_rr() { return getenv("RUNNING_UNDER_RR") != NULL; }

vector<string> read_proc_status_fields(pid_t tid, const char* name,
                                       const char* name2, const char* name3) {
  vector<string> result;
  char buf[1000];
  sprintf(buf, "/proc/%d/status", tid);
  FILE* f = fopen(buf, "r");
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

void copy_file(Task* t, int dest_fd, int src_fd) {
  char buf[1024];
  while (1) {
    ssize_t bytes_read = read(src_fd, buf, sizeof(buf));
    ASSERT(t, bytes_read >= 0);
    if (!bytes_read) {
      break;
    }
    ssize_t bytes_written = write(dest_fd, buf, bytes_read);
    ASSERT(t, bytes_written == bytes_read);
  }
}

void* xmalloc(size_t size) {
  void* mem_ptr = malloc(size);
  if (!mem_ptr) {
    notifying_abort();
  }
  return mem_ptr;
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
  assert(cpuid_data.ecx_in == 0);
  layout.full_size = cpuid_data.out.ecx;
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

uint64_t rr_signal_mask() {
  return signal_bit(PerfCounters::TIME_SLICE_SIGNAL) |
         signal_bit(SYSCALLBUF_DESCHED_SIGNAL);
}

ScopedFd open_socket(const char* address, unsigned short* port,
                     ProbePort probe) {
  ScopedFd listen_fd(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
  if (!listen_fd.is_open()) {
    FATAL() << "Couldn't create socket";
  }

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(address);
  int reuseaddr = 1;
  int ret = setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr,
                       sizeof(reuseaddr));
  if (ret < 0) {
    FATAL() << "Couldn't set SO_REUSEADDR";
  }

  do {
    addr.sin_port = htons(*port);
    ret = ::bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr));
    if (ret && (EADDRINUSE == errno || EACCES == errno || EINVAL == errno)) {
      continue;
    }
    if (ret) {
      FATAL() << "Couldn't bind to port " << *port;
    }

    ret = listen(listen_fd, 1 /*backlogged connection*/);
    if (ret && EADDRINUSE == errno) {
      continue;
    }
    if (ret) {
      FATAL() << "Couldn't listen on port " << *port;
    }
    break;
  } while (++(*port), probe == PROBE_PORT);
  return listen_fd;
}

void notifying_abort() {
  flush_log_buffer();

  char* test_monitor_pid = getenv("RUNNING_UNDER_TEST_MONITOR");
  if (test_monitor_pid) {
    pid_t pid = atoi(test_monitor_pid);
    // Tell test-monitor to wake up and take a snapshot, and wait for it to
    // do so.
    kill(pid, SIGURG);
    sleep(10000);
  } else {
    dump_rr_stack();
  }

  abort();
}

void dump_rr_stack() {
  static const char msg[] = "=== Start rr backtrace:\n";
  write(STDERR_FILENO, msg, sizeof(msg) - 1);
  void* buffer[1024];
  int count = backtrace(buffer, 1024);
  backtrace_symbols_fd(buffer, count, STDERR_FILENO);
  static const char msg2[] = "=== End rr backtrace\n";
  write(STDERR_FILENO, msg2, sizeof(msg2) - 1);
}

void check_for_leaks() {
  if (getenv("RUNNING_UNDER_RR")) {
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

const char* tmp_dir() {
  const char* dir = getenv("RR_TMPDIR");
  if (dir) {
    return dir;
  }
  dir = getenv("TMPDIR");
  if (dir) {
    return dir;
  }
  return "/tmp";
}

TempFile create_temporary_file(const char* pattern) {
  char buf[PATH_MAX];
  snprintf(buf, sizeof(buf) - 1, "%s/%s", tmp_dir(), pattern);
  buf[sizeof(buf) - 1] = 0;
  TempFile result;
  result.fd = mkstemp(buf);
  result.name = buf;
  return result;
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
  int cpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
  return cpus > 0 ? cpus : 1;
}

static const uint8_t rdtsc_insn[] = { 0x0f, 0x31 };
static const uint8_t rdtscp_insn[] = { 0x0f, 0x01, 0xf9 };
static const uint8_t cpuid_insn[] = { 0x0f, 0xa2 };

DisabledInsn disabled_insn_at(Task* t, remote_code_ptr ip) {
  uint8_t insn[sizeof(rdtscp_insn)];
  ssize_t len =
      t->read_bytes_fallible(ip.to_data_ptr<uint8_t>(), sizeof(insn), insn);
  if ((size_t)len >= sizeof(rdtsc_insn) &&
      !memcmp(insn, rdtsc_insn, sizeof(rdtsc_insn))) {
    return DisabledInsn::RDTSC;
  }
  if ((size_t)len >= sizeof(rdtscp_insn) &&
      !memcmp(insn, rdtscp_insn, sizeof(rdtscp_insn))) {
    return DisabledInsn::RDTSCP;
  }
  if ((size_t)len >= sizeof(cpuid_insn) &&
      !memcmp(insn, cpuid_insn, sizeof(cpuid_insn))) {
    return DisabledInsn::CPUID;
  }
  return DisabledInsn::NONE;
}

size_t disabled_insn_len(DisabledInsn insn) {
  if (insn == DisabledInsn::RDTSC) {
    return sizeof(rdtsc_insn);
  } else if (insn == DisabledInsn::RDTSCP) {
    return sizeof(rdtscp_insn);
  } else if (insn == DisabledInsn::CPUID) {
    return sizeof(cpuid_insn);
  } else {
    return 0;
  }
}

/**
 * Read and parse the available CPU list then select a random CPU from the list.
 */
static int get_random_cpu_cgroup() {
  ifstream self_cpuset("/proc/self/cpuset");
  if (!self_cpuset.is_open()) {
    return -1;
  }
  string cpuset_path;
  getline(self_cpuset, cpuset_path);
  self_cpuset.close();
  if (cpuset_path.empty()) {
    return -1;
  }
  ifstream cpuset("/sys/fs/cgroup/cpuset" + cpuset_path + "/cpuset.cpus");
  if (!cpuset.good()) {
    return -1;
  }
  vector<int> cpus;
  while (true) {
    int cpu1;
    cpuset >> cpu1;
    if (cpuset.fail()) {
      return -1;
    }
    cpus.push_back(cpu1);
    char c = cpuset.get();
    if (cpuset.eof() || c == '\n') {
      break;
    } else if (c == ',') {
      continue;
    } else if (c != '-') {
      return -1;
    }
    int cpu2;
    cpuset >> cpu2;
    if (cpuset.fail()) {
      return -1;
    }
    for (int cpu = cpu1 + 1; cpu <= cpu2; cpu++) {
      cpus.push_back(cpu);
    }
    c = cpuset.get();
    if (cpuset.eof() || c == '\n') {
      break;
    } else if (c != ',') {
      return -1;
    }
  }
  return cpus[random() % cpus.size()];
}

/**
 * Pick a CPU at random to bind to, unless --cpu-unbound has been given,
 * in which case we return -1.
 */
int choose_cpu(BindCPU bind_cpu) {
  if (bind_cpu == UNBOUND_CPU) {
    return -1;
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
    return bind_cpu;
  }

  int cpu = get_random_cpu_cgroup();
  if (cpu >= 0) {
    return cpu;
  }
  return random() % get_num_cpus();
}

} // namespace rr
