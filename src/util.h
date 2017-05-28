/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_UTIL_H_
#define RR_UTIL_H_

#include <array>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "Event.h"
#include "ScopedFd.h"
#include "TraceFrame.h"
#include "remote_ptr.h"

#ifndef __has_attribute
#define __has_attribute(x) 0
#endif

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

template <typename T, size_t N> constexpr size_t array_length(T (&)[N]) {
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

enum Completion { COMPLETE, INCOMPLETE };

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
  CPUID_GETEXTENDEDFEATURES = 0x07,
  CPUID_GETXSAVE = 0x0D,
  CPUID_INTELEXTENDED = 0x80000000,
  CPUID_INTELFEATURES,
  CPUID_INTELBRANDSTRING,
  CPUID_INTELBRANDSTRINGMORE,
  CPUID_INTELBRANDSTRINGEND,
};

const int OSXSAVE_FEATURE_FLAG = 1 << 27;
const int AVX_FEATURE_FLAG = 1 << 28;
const int HLE_FEATURE_FLAG = 1 << 4;

/** issue a single request to CPUID. Fits 'intel features', for instance
 *  note that even if only "eax" and "edx" are of interest, other registers
 *  will be modified by the operation, so we need to tell the compiler about it.
 *  'code' is placed in EAX. 'subrequest' is placed in ECX.
 *  *a, *c and *d receive EAX, ECX and EDX respectively.
 */
struct CPUIDData {
  unsigned int eax, ebx, ecx, edx;
};
CPUIDData cpuid(int code, int subrequest);

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

std::vector<std::string> read_proc_status_fields(pid_t tid, const char* name,
                                                 const char* name2 = nullptr,
                                                 const char* name3 = nullptr);

/**
 * Mainline Linux kernels use an invisible (to /proc/<pid>/maps) guard page
 * for stacks. grsecurity kernels don't.
 */
bool uses_invisible_guard_page();

void copy_file(Task* t, int dest_fd, int src_fd);

#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
extern "C" void __msan_unpoison(void*, size_t);
inline void msan_unpoison(void* ptr, size_t n) { __msan_unpoison(ptr, n); };
#else
inline void msan_unpoison(void* ptr, size_t n) {
  (void)ptr;
  (void)n;
};
#endif
#else
inline void msan_unpoison(void* ptr, size_t n) {
  (void)ptr;
  (void)n;
};
#endif

/**
 * Allocate new memory of |size| in bytes. The pointer returned is never NULL.
 * This calls aborts the program if the host runs out of memory.
 */
void* xmalloc(size_t size);

/**
 * Determine if the given capabilities are a subset of the process' current
 * active capabilities.
 */
bool has_effective_caps(uint64_t caps);

/**
 * Determine the size of the xsave area
 */
unsigned int xsave_area_size();

inline uint64_t signal_bit(int sig) { return uint64_t(1) << (sig - 1); }

uint64_t rr_signal_mask();

enum ProbePort { DONT_PROBE = 0, PROBE_PORT };

ScopedFd open_socket(const char* address, unsigned short* port,
                     ProbePort probe);

/**
 * Like `abort`, but tries to wake up test-monitor for a snapshot if possible.
 */
void notifying_abort();

/**
 * Check for leaked mappings etc
 */
void check_for_leaks();

/**
 * Returns $TMPDIR or "/tmp".
 */
const char* tmp_dir();

struct TempFile {
  std::string name;
  ScopedFd fd;
};

/**
 * `pattern is an mkstemp pattern minus any leading path. We'll choose the
 * temp directory ourselves. The file is not automatically deleted, the caller
 * must take care of that.
 */
TempFile create_temporary_file(const char* pattern);

void good_random(void* out, size_t out_len);

std::vector<std::string> current_env();

} // namespace rr

#endif /* RR_UTIL_H_ */
