/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_UTIL_H_
#define RR_UTIL_H_

#include <array>
#include <map>
#include <set>
#include <string>

#include "Event.h"
#include "remote_ptr.h"
#include "ScopedFd.h"
#include "TraceFrame.h"

namespace rr {

/*
 * This file is a dumping ground for functionality that needs to be shared but
 * has no other obvious place to go.
 *
 * We should minimize the amount of code here. Code that's only needed in one
 * place can move out of this file.
 */

class KernelMapping;
class Task;
class TraceFrame;

template <typename T, size_t N> constexpr size_t array_length(T(&)[N]) {
  return N;
}

template <typename T, size_t N>
constexpr size_t array_length(std::array<T, N>&) {
  return N;
}

template <typename T> T return_dummy_value() {
  T v;
  memset(&v, 1, sizeof(T));
  return v;
}
template <typename T> bool check_type_has_no_holes() {
  T v;
  memset(&v, 2, sizeof(T));
  v = return_dummy_value<T>();
  return memchr(&v, 2, sizeof(T)) == NULL;
}
/**
 * Returns true when type T has no holes. Preferably should not be defined
 * at all otherwise.
 * This is not 100% reliable since the check_type_has_no_holes may be
 * compiled to copy holes. However, it has detected at least two bugs.
 */
template <typename T> bool type_has_no_holes() {
  static bool check = check_type_has_no_holes<T>();
  return check;
}

#define SHMEM_FS "/dev/shm"

/* The syscallbuf shared with tracees is created with this prefix
 * followed by the tracee tid, then immediately unlinked and shared
 * anonymously. */
#define SYSCALLBUF_SHMEM_PATH_PREFIX "/tmp/rr-syscallbuf-"

#define PREFIX_FOR_EMPTY_MMAPED_REGIONS "/tmp/rr-emptyfile-"

enum Completion { COMPLETE, INCOMPLETE };

/**
 * During recording, sometimes we need to ensure that an iteration of
 * RecordSession::record_step schedules the same task as in the previous
 * iteration. The PREVENT_SWITCH value indicates that this is required.
 * For example, the futex operation FUTEX_WAKE_OP modifies userspace
 * memory; those changes are only recorded after the system call completes;
 * and they must be replayed before we allow a context switch to a woken-up
 * task (because the kernel guarantees those effects are seen by woken-up
 * tasks).
 * Entering a potentially blocking system call must use ALLOW_SWITCH, or
 * we risk deadlock. Most non-blocking system calls could use PREVENT_SWITCH
 * or ALLOW_SWITCH; for simplicity we use ALLOW_SWITCH to indicate a call could
 * block and PREVENT_SWITCH otherwise.
 * Note that even if a system call uses PREVENT_SWITCH, as soon as we've
 * recorded the completion of the system call, we can switch to another task.
 */
enum Switchable { PREVENT_SWITCH, ALLOW_SWITCH };

/**
 * Create a file named |filename| and dump |buf_len| words in |buf| to
 * that file, starting with a line containing |label|.  |start_addr|
 * is the client address at which |buf| resides, if meaningful.
 * |start_addr| is used to compute the output lines of words, which
 * look like "0xValue | [0xAddr]".
 */
void dump_binary_data(const char* filename, const char* label,
                      const uint32_t* buf, size_t buf_len,
                      remote_ptr<void> start_addr);

/**
 * Format a suitable filename within the trace directory for dumping
 * information about |t| at the current global time, to a file that
 * contains |tag|.  The constructed filename is returned through
 * |filename|.  For example, a filengit logame for a task with tid 12345 at
 * time 111, for a file tagged "foo", would be something like
 * "trace_0/12345_111_foo".  The returned name is not guaranteed to be
 * unique, caveat emptor.
 */
void format_dump_filename(Task* t, TraceFrame::Time global_time,
                          const char* tag, char* filename,
                          size_t filename_size);

/**
 * Return true if the user requested memory be dumped at |f|.
 */
bool should_dump_memory(const TraceFrame& f);
/**
 * Dump all of the memory in |t|'s address to the file
 * "[trace_dir]/[t->tid]_[global_time]_[tag]".
 */
void dump_process_memory(Task* t, TraceFrame::Time global_time,
                         const char* tag);

/**
 * Return true if the user has requested |t|'s memory be
 * checksummed at |f|.
 */
bool should_checksum(const TraceFrame& f);
/**
 * Write a checksum of each mapped region in |t|'s address space to a
 * special log, where it can be read by |validate_process_memory()|
 * during replay.
 */
void checksum_process_memory(Task* t, TraceFrame::Time global_time);
/**
 * Validate the checksum of |t|'s address space that was written
 * during recording.
 */
void validate_process_memory(Task* t, TraceFrame::Time global_time);

/**
 * Return nonzero if the rr session is probably not interactive (that
 * is, there's probably no user watching or interacting with rr), and
 * so asking for user input or other actions is probably pointless.
 */
bool probably_not_interactive(int fd = STDERR_FILENO);

/**
 * Convert the flags passed to the clone() syscall, |flags_arg|, into
 * the format understood by Task::clone().
 */
int clone_flags_to_task_flags(int flags_arg);

/**
 * Return the argument rounded up to the nearest multiple of the
 * system |page_size()|.
 */
size_t ceil_page_size(size_t sz);
remote_ptr<void> ceil_page_size(remote_ptr<void> addr);

/**
 * Return the argument rounded down to the nearest multiple of the
 * system |page_size()|.
 */
size_t floor_page_size(size_t sz);
remote_ptr<void> floor_page_size(remote_ptr<void> addr);

/** Return the system page size. */
size_t page_size();

/** Return the default action of |sig|. */
enum signal_action { DUMP_CORE, TERMINATE, CONTINUE, STOP, IGNORE };
signal_action default_action(int sig);

SignalDeterministic is_deterministic_signal(Task* t);

/**
 * Return nonzero if a mapping of |filename| with metadata |stat|,
 * using |flags| and |prot|, should almost certainly be copied to
 * trace; i.e., the file contents are likely to change in the interval
 * between recording and replay.  Zero is returned /if we think we can
 * get away/ with not copying the region.  That doesn't mean it's
 * necessarily safe to skip copying!
 */
bool should_copy_mmap_region(const KernelMapping& mapping,
                             const struct stat& stat);

/**
 * Ensure that the shmem segment referred to by |fd| has exactly the
 * size |num_bytes|.
 */
void resize_shmem_segment(ScopedFd& fd, uint64_t num_bytes);

enum cpuid_requests {
  CPUID_GETVENDORSTRING,
  CPUID_GETFEATURES,
  CPUID_GETTLB,
  CPUID_GETSERIAL,
  CPUID_GETXSAVE = 0x0D,
  CPUID_INTELEXTENDED = 0x80000000,
  CPUID_INTELFEATURES,
  CPUID_INTELBRANDSTRING,
  CPUID_INTELBRANDSTRINGMORE,
  CPUID_INTELBRANDSTRINGEND,
};

/** issue a single request to CPUID. Fits 'intel features', for instance
 *  note that even if only "eax" and "edx" are of interest, other registers
 *  will be modified by the operation, so we need to tell the compiler about it.
 *  'code' is placed in EAX. 'subrequest' is placed in ECX.
 *  *a, *c and *d receive EAX, ECX and EDX respectively.
 */
void cpuid(int code, int subrequest, unsigned int* a, unsigned int* c,
           unsigned int* d);

struct CloneParameters {
  remote_ptr<void> stack;
  remote_ptr<int> ptid;
  remote_ptr<void> tls;
  remote_ptr<int> ctid;
};
/**
 * Extract various clone(2) parameters out of the given Task's registers.
 */
CloneParameters extract_clone_parameters(Task* t);

/**
 * Read the ELF CLASS from the given filename. If it's unable to be read,
 * return ELFCLASSNONE. If it's not an ELF file, return NOT_ELF.
 */
const int NOT_ELF = 0x10000;
int read_elf_class(const std::string& filename);

bool trace_instructions_up_to_event(TraceFrame::Time event);

/* Helpful for broken debuggers */

void dump_task_set(const std::set<Task*>& tasks);

void dump_task_map(const std::map<pid_t, Task*>& tasks);

std::string real_path(const std::string& path);

std::string exe_directory();

/**
 * Get the current time from the preferred monotonic clock in units of
 * seconds, relative to an unspecific point in the past.
 */
double monotonic_now_sec();

bool running_under_rr();

} // namespace rr

#endif /* RR_UTIL_H_ */
