/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "Util"

//#define FIRST_INTERESTING_EVENT 10700
//#define LAST_INTERESTING_EVENT 10900

#include "util.h"

#include <assert.h>
#include <elf.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/magic.h>
#include <string.h>
#include <stdlib.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "preload/preload_interface.h"

#include "Flags.h"
#include "kernel_abi.h"
#include "kernel_metadata.h"
#include "log.h"
#include "ReplaySession.h"
#include "task.h"
#include "TraceStream.h"

using namespace std;
using namespace rr;

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
  // See task.h for description of the flags.
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

bool should_dump_memory(Task* t, const TraceFrame& f) {
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
         flags->dump_at == int(f.time());
}

void dump_process_memory(Task* t, TraceFrame::Time global_time,
                         const char* tag) {
  char filename[PATH_MAX];
  FILE* dump_file;

  format_dump_filename(t, global_time, tag, filename, sizeof(filename));
  dump_file = fopen64(filename, "w");

  const AddressSpace& as = *(t->vm());
  for (auto& kv : as.memmap()) {
    const Mapping& first = kv.first;
    const MappableResource& second = kv.second;
    vector<uint8_t> mem;
    mem.resize(first.num_bytes());

    ssize_t mem_len =
        t->read_bytes_fallible(first.start, first.num_bytes(), mem.data());
    mem_len = max(ssize_t(0), mem_len);

    string label = first.str() + ' ' + second.str();

    if (!is_start_of_scratch_region(t, first.start)) {
      dump_binary_chunk(dump_file, label.c_str(), (const uint32_t*)mem.data(),
                        mem_len / sizeof(uint32_t), first.start);
    }
  }
  fclose(dump_file);
}

static void notify_checksum_error(Task* t, TraceFrame::Time global_time,
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
enum ChecksumMode {
  STORE_CHECKSUMS,
  VALIDATE_CHECKSUMS
};
struct checksum_iterator_data {
  ChecksumMode mode;
  FILE* checksums_file;
  TraceFrame::Time global_time;
};

static bool checksum_segment_filter(const Mapping& m,
                                    const MappableResource& r) {
  struct stat st;
  int may_diverge;

  if (stat(r.fsname.c_str(), &st)) {
    /* If there's no persistent resource backing this
     * mapping, we should expect it to change. */
    LOG(debug) << "CHECKSUMMING unlinked '" << r.fsname << "'";
    return true;
  }
  /* If we're pretty sure the backing resource is effectively
   * immutable, skip checksumming, it's a waste of time.  Except
   * if the mapping is mutable, for example the rw data segment
   * of a system library, then it's interesting. */
  may_diverge = should_copy_mmap_region(r.fsname, &st, m.prot, m.flags) ||
                (PROT_WRITE & m.prot);
  LOG(debug) << (may_diverge ? "CHECKSUMMING" : "  skipping") << " '"
             << r.fsname << "'";
  return may_diverge;
}

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

  const AddressSpace& as = *(t->vm());
  for (auto& kv : as.memmap()) {
    const Mapping& first = kv.first;
    const MappableResource& second = kv.second;

    vector<uint8_t> mem;
    ssize_t valid_mem_len = 0;

    if (checksum_segment_filter(first, second)) {
      mem.resize(first.num_bytes());
      valid_mem_len =
          t->read_bytes_fallible(first.start, first.num_bytes(), mem.data());
      valid_mem_len = max(ssize_t(0), valid_mem_len);
    }

    unsigned* buf = (unsigned*)mem.data();
    unsigned checksum = 0;
    int i;

    if (second.fsname.find(SYSCALLBUF_SHMEM_PATH_PREFIX) != string::npos) {
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
      auto child_hdr = first.start.cast<struct syscallbuf_hdr>();
      auto hdr = t->read_mem(child_hdr);
      valid_mem_len = !buf ? 0 : sizeof(hdr) + hdr.num_rec_bytes +
                                     sizeof(struct syscallbuf_record);
    }

    ASSERT(t, buf || valid_mem_len == 0);
    for (i = 0; i < ssize_t(valid_mem_len / sizeof(*buf)); ++i) {
      checksum += buf[i];
    }

    string raw_map_line = first.str() + ' ' + second.str();
    if (STORE_CHECKSUMS == c.mode) {
      fprintf(c.checksums_file, "(%x) %s\n", checksum, raw_map_line.c_str());
    } else {
      char line[1024];
      unsigned rec_checksum;
      unsigned long rec_start;
      unsigned long rec_end;
      int nparsed;

      fgets(line, sizeof(line), c.checksums_file);
      nparsed =
          sscanf(line, "(%x) %lx-%lx", &rec_checksum, &rec_start, &rec_end);
      remote_ptr<void> rec_start_addr = rec_start;
      remote_ptr<void> rec_end_addr = rec_end;
      ASSERT(t, 3 == nparsed) << "Only parsed " << nparsed << " items";

      ASSERT(t, rec_start_addr == first.start && rec_end_addr == first.end)
          << "Segment " << rec_start_addr << "-" << rec_end_addr
          << " changed to " << first << "??";

      if (is_start_of_scratch_region(t, rec_start_addr)) {
        /* Replay doesn't touch scratch regions, so
         * their contents are allowed to diverge.
         * Tracees can't observe those segments unless
         * they do something sneaky (or disastrously
         * buggy). */
        LOG(debug) << "Not validating scratch starting at 0x" << hex
                   << rec_start_addr << dec;
        continue;
      }
      if (checksum != rec_checksum) {
        notify_checksum_error(t, c.global_time, checksum, rec_checksum,
                              raw_map_line.c_str());
      }
    }
  }

  fclose(c.checksums_file);
}

bool should_checksum(Task* t, const TraceFrame& f) {
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
  if (SIGRTMIN <= sig && sig <= SIGRTMAX) {
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

SignalDeterministic is_deterministic_signal(const siginfo_t& si) {
  switch (si.si_signo) {
    /* These signals may be delivered deterministically;
     * we'll check for sure below. */
    case SIGILL:
    case SIGTRAP:
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
    default:
      /* All other signals can never be delivered
       * deterministically (to the approximation required by
       * rr). */
      return NONDETERMINISTIC_SIG;
  }
}

bool possibly_destabilizing_signal(Task* t, int sig,
                                   SignalDeterministic deterministic) {
  signal_action action = default_action(sig);
  if (action != DUMP_CORE && action != TERMINATE) {
    // If the default action doesn't kill the process, it won't die.
    return false;
  }

  if (t->is_sig_ignored(sig)) {
    // Deterministic fatal signals can't be ignored.
    return deterministic == DETERMINISTIC_SIG;
  }
  if (!t->signal_has_user_handler(sig)) {
    // The default action is going to happen: killing the process.
    return true;
  }
  // If the signal's blocked, user handlers aren't going to run and the process
  // will die.
  return t->is_sig_blocked(sig);
}

static bool has_fs_name(const string& path) {
  struct stat dummy;
  return 0 == stat(path.c_str(), &dummy);
}

static bool is_tmp_file(const string& path) {
  struct statfs sfs;
  statfs(path.c_str(), &sfs);
  return (TMPFS_MAGIC == sfs.f_type
                         // In observed configurations of Ubuntu 13.10, /tmp is
                         // a folder in the / fs, not a separate tmpfs.
          ||
          path.c_str() == strstr(path.c_str(), "/tmp/"));
}

bool should_copy_mmap_region(const string& file_name, const struct stat* stat,
                             int prot, int flags) {
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
  if (private_mapping && (prot & PROT_EXEC)) {
    /* We currently don't record the images that we
     * exec(). Since we're being optimistic there (*cough*
     * *cough*), we're doing no worse (in theory) by being
     * optimistic about the shared libraries too, most of
     * which are system libraries. */
    LOG(debug) << "  (no copy for +x private mapping " << file_name << ")";
    return false;
  }
  if (private_mapping && (0111 & stat->st_mode)) {
    /* A private mapping of an executable file usually
     * indicates mapping data sections of object files.
     * Since we're already assuming those change very
     * infrequently, we can avoid copying the data
     * sections too. */
    LOG(debug) << "  (no copy for private mapping of +x " << file_name << ")";
    return false;
  }

  // TODO: using "can the euid of the rr process write this
  // file" as an approximation of whether the tracee can write
  // the file.  If the tracee is messing around with
  // set*[gu]id(), the real answer may be different.
  bool can_write_file = (0 == access(file_name.c_str(), W_OK));

  if (!can_write_file && 0 == stat->st_uid) {
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
  if (!(0222 & stat->st_mode)) {
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
            << "); uid:" << stat->st_uid << " mode:" << stat->st_mode;
  }
  return true;
}

ScopedFd create_shmem_segment(const string& name, size_t num_bytes) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path) - 1, "%s/%s", SHMEM_FS, name.c_str());

  ScopedFd fd = open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
  if (0 > fd) {
    FATAL() << "Failed to create shmem segment " << path;
  }
  /* Remove the fs name so that we don't have to worry about
   * cleaning up this segment in error conditions. */
  unlink(path);
  resize_shmem_segment(fd, num_bytes);

  LOG(debug) << "created shmem segment " << path;
  return fd;
}

void resize_shmem_segment(ScopedFd& fd, size_t num_bytes) {
  if (ftruncate(fd, num_bytes)) {
    FATAL() << "Failed to resize shmem to " << num_bytes;
  }
}

// TODO de-dup
static void advance_syscall(Task* t) {
  do {
    t->cont_syscall();
  } while (t->is_ptrace_seccomp_event() ||
           ReplaySession::is_ignored_signal(t->pending_sig()));
  assert(t->ptrace_event() == 0);
}

void destroy_buffers(Task* t) {
  // NB: we have to pay all this complexity here because glibc
  // makes its SYS_exit call through an inline int $0x80 insn,
  // instead of going through the vdso.  There may be a deep
  // reason for why it does that, but if it starts going through
  // the vdso in the future, this code can be eliminated in
  // favor of a *much* simpler vsyscall SYS_exit hook in the
  // preload lib.
  Registers exit_regs = t->regs();
  ASSERT(t, is_exit_syscall(exit_regs.original_syscallno(), t->arch()))
      << "Tracee should have been at exit, but instead at "
      << t->syscall_name(exit_regs.original_syscallno());

  // The tracee is at the entry to SYS_exit, but hasn't started
  // the call yet.  We can't directly start injecting syscalls
  // because the tracee is still in the kernel.  And obviously,
  // if we finish the SYS_exit syscall, the tracee isn't around
  // anymore.
  //
  // So hijack this SYS_exit call and rewrite it into a harmless
  // one that we can exit successfully, SYS_gettid here (though
  // that choice is arbitrary).
  exit_regs.set_original_syscallno(syscall_number_for_gettid(t->arch()));
  t->set_regs(exit_regs);
  // This exits the hijacked SYS_gettid.  Now the tracee is
  // ready to do our bidding.
  advance_syscall(t);

  // Restore these regs to what they would have been just before
  // the tracee trapped at SYS_exit.  When we've finished
  // cleanup, we'll restart the SYS_exit call.
  exit_regs.set_original_syscallno(-1);
  exit_regs.set_syscallno(syscall_number_for_exit(t->arch()));
  exit_regs.set_ip(exit_regs.ip() - syscall_instruction_length(t->arch()));
  ASSERT(t, is_at_syscall_instruction(t, exit_regs.ip()))
      << "Tracee should have entered through int $0x80.";

  // Do the actual buffer and fd cleanup.
  t->destroy_buffers();

  // Restart the SYS_exit call.
  t->set_regs(exit_regs);
  advance_syscall(t);
}

void cpuid(int code, int subrequest, unsigned int* a, unsigned int* c,
           unsigned int* d) {
  asm volatile("cpuid"
               : "=a"(*a), "=c"(*c), "=d"(*d)
               : "a"(code), "c"(subrequest)
               : "ebx");
}

void set_cpu_affinity(int cpu) {
  assert(cpu >= 0);

  cpu_set_t mask;
  CPU_ZERO(&mask);
  CPU_SET(cpu, &mask);
  if (0 > sched_setaffinity(0, sizeof(mask), &mask)) {
    FATAL() << "Couldn't bind to CPU " << cpu;
  }
}

int get_num_cpus() {
  int cpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
  return cpus > 0 ? cpus : 1;
}

template <typename Arch>
static void extract_clone_parameters_arch(const Registers& regs,
                                          remote_ptr<void>* stack,
                                          remote_ptr<int>* parent_tid,
                                          remote_ptr<void>* tls,
                                          remote_ptr<int>* child_tid) {
  switch (Arch::clone_parameter_ordering) {
    case Arch::FlagsStackParentTLSChild:
      if (stack) {
        *stack = regs.arg2();
      }
      if (parent_tid) {
        *parent_tid = regs.arg3();
      }
      if (tls) {
        *tls = regs.arg4();
      }
      if (child_tid) {
        *child_tid = regs.arg5();
      }
      break;
    case Arch::FlagsStackParentChildTLS:
      if (stack) {
        *stack = regs.arg2();
      }
      if (parent_tid) {
        *parent_tid = regs.arg3();
      }
      if (child_tid) {
        *child_tid = regs.arg4();
      }
      if (tls) {
        *tls = regs.arg5();
      }
      break;
  }
}

void extract_clone_parameters(Task* t, remote_ptr<void>* stack,
                              remote_ptr<int>* parent_tid,
                              remote_ptr<void>* tls,
                              remote_ptr<int>* child_tid) {
  RR_ARCH_FUNCTION(extract_clone_parameters_arch, t->arch(), t->regs(), stack,
                   parent_tid, tls, child_tid);
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
