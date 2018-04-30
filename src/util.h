/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_UTIL_H_
#define RR_UTIL_H_

#include "signal.h"

#include <array>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "ScopedFd.h"
#include "TraceFrame.h"
#include "remote_ptr.h"

namespace rr {

/*
 * This file is a dumping ground for functionality that needs to be shared but
 * has no other obvious place to go.
 *
 * We should minimize the amount of code here. Code that's only needed in one
 * place can move out of this file.
 */

struct Event;
class KernelMapping;
class Task;
class TraceFrame;

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
void format_dump_filename(Task* t, FrameTime global_time, const char* tag,
                          char* filename, size_t filename_size);

/**
 * Return true if the user requested memory be dumped at this event/time.
 */
bool should_dump_memory(const Event& event, FrameTime time);
/**
 * Dump all of the memory in |t|'s address to the file
 * "[trace_dir]/[t->tid]_[global_time]_[tag]".
 */
void dump_process_memory(Task* t, FrameTime global_time, const char* tag);

/**
 * Return true if the user has requested |t|'s memory be
 * checksummed at this event/time.
 */
bool should_checksum(const Event& event, FrameTime time);
/**
 * Write a checksum of each mapped region in |t|'s address space to a
 * special log, where it can be read by |validate_process_memory()|
 * during replay.
 */
void checksum_process_memory(Task* t, FrameTime global_time);
/**
 * Validate the checksum of |t|'s address space that was written
 * during recording.
 */
void validate_process_memory(Task* t, FrameTime global_time);

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
 * Return nonzero if a mapping of |mapping| should almost certainly be copied to
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
  CPUID_GETCACHEPARAMS = 0x04,
  CPUID_GETEXTENDEDFEATURES = 0x07,
  CPUID_GETEXTENDEDTOPOLOGY = 0x0B,
  CPUID_GETXSAVE = 0x0D,
  CPUID_GETRDTMONITORING = 0x0F,
  CPUID_GETRDTALLOCATION = 0x10,
  CPUID_GETSGX = 0x12,
  CPUID_GETPT = 0x14,
  CPUID_GETSOC = 0x17,
  CPUID_HYPERVISOR = 0x40000000,
  CPUID_INTELEXTENDED = 0x80000000,
  CPUID_INTELFEATURES,
  CPUID_INTELBRANDSTRING,
  CPUID_INTELBRANDSTRINGMORE,
  CPUID_INTELBRANDSTRINGEND,
};

const int OSXSAVE_FEATURE_FLAG = 1 << 27;
const int AVX_FEATURE_FLAG = 1 << 28;
const int HLE_FEATURE_FLAG = 1 << 4;
const int XSAVEC_FEATURE_FLAG = 1 << 1;

/** issue a single request to CPUID. Fits 'intel features', for instance
 *  note that even if only "eax" and "edx" are of interest, other registers
 *  will be modified by the operation, so we need to tell the compiler about it.
 *  'code' is placed in EAX. 'subrequest' is placed in ECX.
 *  *a, *c and *d receive EAX, ECX and EDX respectively.
 */
struct CPUIDData {
  uint32_t eax, ebx, ecx, edx;
};
CPUIDData cpuid(uint32_t code, uint32_t subrequest);

/**
 * Check OSXSAVE flag.
 */
bool xsave_enabled();
/**
 * Fetch current XCR0 value using XGETBV instruction.
 */
uint64_t xcr0();

/**
 * Return all CPUID values supported by this CPU.
 */
struct CPUIDRecord {
  uint32_t eax_in;
  // UINT32_MAX means ECX not relevant
  uint32_t ecx_in;
  CPUIDData out;
};
std::vector<CPUIDRecord> all_cpuid_records();

/**
 * Returns true if CPUID faulting is supported by the kernel and hardware and
 * is actually working.
 */
bool cpuid_faulting_works();

/**
 * Locate a CPUID record for the give parameters, or return nullptr if there
 * isn't one.
 */
const CPUIDRecord* find_cpuid_record(const std::vector<CPUIDRecord>& records,
                                     uint32_t eax, uint32_t ecx);

/**
 * Return true if the trace's CPUID values are "compatible enough" with our
 * CPU's CPUID values.
 */
bool cpuid_compatible(const std::vector<CPUIDRecord>& trace_records);

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

bool trace_instructions_up_to_event(FrameTime event);

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

bool is_zombie_process(pid_t pid);

/**
 * Mainline Linux kernels use an invisible (to /proc/<pid>/maps) guard page
 * for stacks. grsecurity kernels don't.
 */
bool uses_invisible_guard_page();

bool copy_file(int dest_fd, int src_fd);

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

struct XSaveFeatureLayout {
  uint32_t offset;
  uint32_t size;
};

struct XSaveLayout {
  size_t full_size;
  uint64_t supported_feature_bits;
  std::vector<XSaveFeatureLayout> feature_layouts;
};

/**
 * Determine the layout of the native XSAVE area
 */
const XSaveLayout& xsave_native_layout();

/**
 * Determine the layout of the XSAVE area from a trace
 */
XSaveLayout xsave_layout_from_trace(const std::vector<CPUIDRecord> records);

/**
 * 0 means XSAVE not detected
 */
inline size_t xsave_area_size() { return xsave_native_layout().full_size; }

inline sig_set_t signal_bit(int sig) { return sig_set_t(1) << (sig - 1); }

uint64_t rr_signal_mask();

inline bool is_kernel_trap(int si_code) {
  /* XXX unable to find docs on which of these "should" be
   * right.  The SI_KERNEL code is seen in the int3 test, so we
   * at least need to handle that. */
  return si_code == TRAP_BRKPT || si_code == SI_KERNEL;
}

enum ProbePort { DONT_PROBE = 0, PROBE_PORT };

ScopedFd open_socket(const char* address, unsigned short* port,
                     ProbePort probe);

/**
 * Like `abort`, but tries to wake up test-monitor for a snapshot if possible.
 */
void notifying_abort();

/**
 * Dump the current rr stack
 */
void dump_rr_stack();

/**
 * Check for leaked mappings etc
 */
void check_for_leaks();

/**
 * Create directory `str`, creating parent directories as needed.
 * `dir_type` is printed in error messages. Fails if the resulting directory
 * is not writeable.
 */
void ensure_dir(const std::string& dir, const char* dir_type, mode_t mode);

/**
 * Returns $TMPDIR or "/tmp". We call ensure_dir to make sure the directory
 * exists and is writeable.
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

int get_num_cpus();

enum class TrappedInstruction {
  NONE = 0,
  RDTSC = 1,
  RDTSCP = 2,
  CPUID = 3,
};

/* If |t->ip()| points at a disabled instruction, return the instruction */
TrappedInstruction trapped_instruction_at(Task* t, remote_code_ptr ip);

/* Return the length of the TrappedInstruction */
size_t trapped_instruction_len(TrappedInstruction insn);

/**
 * BIND_CPU means binding to a randomly chosen CPU.
 * UNBOUND_CPU means not binding to a particular CPU.
 * A non-negative value means binding to the specific CPU number.
 */
enum BindCPU { BIND_CPU = -2, UNBOUND_CPU = -1 };

/* Convert a BindCPU to a specific CPU number */
int choose_cpu(BindCPU bind_cpu);

/* Updates an IEEE 802.3 CRC-32 least significant bit first from each byte in
 * |buf|.  Pre- and post-conditioning is not performed in this function and so
 * should be performed by the caller, as required. */
uint32_t crc32(uint32_t crc, unsigned char* buf, size_t len);

/* Like write(2) but any error or "device full" is treated as fatal. We also
 * ensure that all bytes are written by looping on short writes. */
void write_all(int fd, const void* buf, size_t size);

/* Returns true if |path| is an accessible directory. Returns false if there
 * was an error.
 */
bool is_directory(const char* path);

/**
 * Read bytes from `fd` into `buf` from `offset` until the read returns an
 * error or 0 or the buffer is full. Returns total bytes read or -1 for error.
 */
ssize_t read_to_end(const ScopedFd& fd, size_t offset, void* buf, size_t size);

/**
 * Raise resource limits, in particular the open file descriptor count.
 */
void raise_resource_limits();

/**
 * Restore the initial resource limits for this process.
 */
void restore_initial_resource_limits();

} // namespace rr

#endif /* RR_UTIL_H_ */
