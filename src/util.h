/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_UTIL_H_
#define RR_UTIL_H_

#include <signal.h>
#include <stdio.h>
#include <math.h>

#include <array>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#if defined(__i386__) || defined(__x86_64__)
#include <x86intrin.h>
#endif

#include "MemoryRange.h"
#include "ScopedFd.h"
#include "TraceFrame.h"
#include "remote_ptr.h"
#include "kernel_supplement.h"
#include <capnp/c++.capnp.h>
#include "rr_trace.capnp.h"

/* This is pretty arbitrary. On Linux SIGPWR is sent to PID 1 (init) on
 * power failure, and it's unlikely rr will be recording that.
 * Note that SIGUNUSED means SIGSYS which actually *is* used (by seccomp),
 * so we can't use it. */
#define SYSCALLBUF_DEFAULT_DESCHED_SIGNAL SIGPWR

#define UNUSED(expr)     \
  do {                   \
    if (expr) {          \
      (void)0;           \
    }                    \
  } while (0)

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
class RecordTask;
class ReplayTask;

typedef int BindCPU;

enum Completion { COMPLETE, INCOMPLETE };

/**
 * Returns a vector containing the raw data you can get from getauxval.
 */
std::vector<uint8_t> read_auxv(Task* t);

/**
 * Returns the base address where the interpreter is mapped.
 */
remote_ptr<void> read_interpreter_base(std::vector<uint8_t> auxv);

/**
 * Returns a string containing the file name of the interpreter.
 */
std::string read_ld_path(Task* t, remote_ptr<void> interpreter_base);

/**
 * Returns a vector containing the environment strings.
 */
std::vector<std::string> read_env(Task* t);

void patch_auxv_vdso(RecordTask* t, uintptr_t search, uintptr_t new_entry);

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
 * contains |tag|.  For example, a file for a task with tid 12345 at
 * time 111, for a file tagged "foo", would be something like
 * "trace_0/111_12345_foo".  The returned name is not guaranteed to be
 * unique, caveat emptor.
 */
std::string format_dump_filename(Task* t, FrameTime global_time,
                                 const char* tag);

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
void checksum_process_memory(RecordTask* t, FrameTime global_time);
/**
 * Validate the checksum of |t|'s address space that was written
 * during recording.
 */
void validate_process_memory(ReplayTask* t, FrameTime global_time);

/**
 * Write raw PT data to a file in the trace dir.
 */
void write_pt_data(Task* t, FrameTime global_time,
                   const std::vector<std::vector<uint8_t>>& data);

/**
 * Read raw PT data to a file in the trace dir. Returns an empty vector if none found.
 */
std::vector<uint8_t> read_pt_data(Task* t, FrameTime global_time);

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
                             const std::string &file_name,
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
  CPUID_AMD_CACHE_TOPOLOGY = 0x8000001D,
  CPUID_AMD_PLATFORM_QOS = 0x80000020
};

const int XSAVE_FEATURE_FLAG = 1 << 26;
const int OSXSAVE_FEATURE_FLAG = 1 << 27;
const int AVX_FEATURE_FLAG = 1 << 28;
const int HLE_FEATURE_FLAG = 1 << 4;
const int XSAVEC_FEATURE_FLAG = 1 << 1;
const int PKU_FEATURE_FLAG = 1 << 3;

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
 * Check whether the given result of cpuid(CPUID_GETVENDORSTRING) indicates
 * an AMD processor.
 */
bool is_cpu_vendor_amd(CPUIDData vendor_string);

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

/**
 * Return true if the CPU stores 0 for FIP/FDP in an XSAVE when no x87 exception
 * is pending.
 */
bool cpu_has_xsave_fip_fdp_quirk();

/**
 * CPU only sets FDP when an unmasked x87 exception is generated.
 */
bool cpu_has_fdp_exception_only_quirk();

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

std::string resource_path();

/**
 * Get the current time from the preferred monotonic clock in units of
 * seconds, relative to an unspecific point in the past.
 */
double monotonic_now_sec();

bool running_under_rr(bool cache = true);

std::vector<int> read_all_proc_fds(pid_t tid);

std::vector<std::string> read_proc_status_fields(pid_t tid, const char* name,
                                                 const char* name2 = nullptr,
                                                 const char* name3 = nullptr);

/**
 * Mainline Linux kernels use an invisible (to /proc/<pid>/maps) guard page
 * for stacks. grsecurity kernels don't.
 */
bool uses_invisible_guard_page();

/**
 * Search /proc/net/ for a socket of the correct family matching the provided fd.
 * If found, returns the local and remote addresses in out and returns true.
 * Otherwise, returns false.
 */
bool read_proc_net_socket_addresses(Task* t, int fd, std::array<typename NativeArch::sockaddr_storage, 2>& out);

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

inline bool is_kernel_trap(int si_code) {
  /* XXX unable to find docs on which of these "should" be
   * right.  The SI_KERNEL code is seen in the int3 test, so we
   * at least need to handle that. */
  return si_code == TRAP_TRACE || si_code == TRAP_BRKPT || si_code == TRAP_HWBKPT || si_code == SI_KERNEL;
}

enum ProbePort { DONT_PROBE = 0, PROBE_PORT };

struct OpenedSocket {
  ScopedFd fd;
  int domain;
  std::string host;
  unsigned short port;
};

// Open a socket bound to the given address and port.
// If PROBE_PORT is set, probes for a usable port and sets it
// in *port.
// If `host` is empty, binds to localhost.
// Returns the actual bound address, socket domain, and port.
// Selects IPv4 or IPv6 automatically depending on what's in the
// host address and what's available.
OpenedSocket open_socket(const std::string& host, unsigned short port,
                         ProbePort probe);

/**
 * Like `abort`, but tries to wake up test-monitor for a snapshot if possible.
 * We try not to allocate.
 */
void notifying_abort();

/**
 * Dump the current rr stack to the given file.
 * We try not to allocate.
 */
void dump_rr_stack(ScopedFd& fd);

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

/**
 * Opens a temporary file backed by RAM.
 */
ScopedFd open_memory_file(const std::string &name);

void good_random(void* out, size_t out_len);

std::vector<std::string> current_env();

/**
 * Returns the number of CPUs online. This is useful for sizing a thread
 * pool.
 * We might see CPUs with an index >= this value, so this is not useful
 * for comparing with CPU indices.
 */
int get_num_cpus();

enum class SpecialInstOpcode {
  NONE,
  ARM_MRS_CNTFRQ_EL0,
  ARM_MRS_CNTVCT_EL0,
  ARM_MRS_CNTVCTSS_EL0,
  X86_RDTSC,
  X86_RDTSCP,
  X86_CPUID,
  X86_INT3,
  X86_PUSHF,
  X86_PUSHF16,
};

struct SpecialInst {
  SpecialInstOpcode opcode;
  unsigned regno = 0;
};

/* If |t->ip()| points at a decoded instruction, return the instruction */
SpecialInst special_instruction_at(Task* t, remote_code_ptr ip);

extern const uint8_t rdtsc_insn[2];

/* Return the length of the TrappedInstruction */
size_t special_instruction_len(SpecialInstOpcode insn);

/**
 * Certain instructions generate deterministic signals but also advance pc.
 * Look *backwards* and see if this was one of them.
 */
bool is_advanced_pc_and_signaled_instruction(Task* t, remote_code_ptr ip);

/**
 * BIND_CPU means binding to a randomly chosen CPU.
 * UNBOUND_CPU means not binding to a particular CPU.
 * A non-negative value means binding to the specific CPU number.
 */
enum { BIND_CPU = -2, UNBOUND_CPU = -1 };

/* Get the path of the cpu lock file */
std::string get_cpu_lock_file();

/* Convert a BindCPU to a specific CPU number. If possible, the cpu_lock_fd_out
   will be set to an fd that holds an advisory fcntl lock for the chosen CPU
   for coordination with other rr processes */
int choose_cpu(BindCPU bind_cpu, ScopedFd& cpu_lock_fd_out);

/* Updates an IEEE 802.3 CRC-32 least significant bit first from each byte in
 * |buf|.  Pre- and post-conditioning is not performed in this function and so
 * should be performed by the caller, as required. */
uint32_t crc32(uint32_t crc, unsigned char* buf, size_t len);

/* Like write(2) but any error or "device full" is treated as fatal. We also
 * ensure that all bytes are written by looping on short writes. */
void write_all(int fd, const void* buf, size_t size);

/* Like pwrite64(2) but we try to write all bytes by looping on short writes. */
ssize_t pwrite_all_fallible(int fd, const void* buf, size_t size, off64_t offset);

/* Returns true if |path| is an accessible directory. Returns false if there
 * was an error.
 */
bool is_directory(const char* path);

/*
 * Returns a pointer to the filename portion of the path.
 * That is the position after the last '/'
 */
const char* filename(const char* path);

/*
 * Returns whether a trace is at the path by checking for a version or
 * incomplete file.
 * Will set errno, if false.
 */
bool is_trace(const std::string& path);

/*
 * Returns whether the latest_trace symlink (if any) points to |trace|.
 */
bool is_latest_trace(const std::string& trace);

/*
 * Deletes the latest_trace symlink, logs an error and returns false on failure.
 */
bool remove_latest_trace_symlink();

/*
 * Returns whether |entry| is a valid trace name.
 * If invalid, optional out-param |reason| will be set to the reason.
 * I.e. does not start with . or #, does not end with ~, is neither cpu_lock
 * nor latest_trace.
 */
bool is_valid_trace_name(const std::string& entry,
                         std::string* reason = nullptr);

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

/**
 * Return the word size for the architecture.
 */
size_t word_size(SupportedArch arch);

/**
 * Print JSON-escaped version of the string, including double-quotes.
 */
std::string json_escape(const std::string& str, size_t pos = 0);

void sleep_time(double t);

/**
 * Normalize a file name by lexically resolving `.`,`..`,`//`
 */
void normalize_file_name(std::string& s);

enum NestedBehavior {
  NESTED_ERROR,
  NESTED_IGNORE,
  NESTED_DETACH,
  NESTED_RELEASE,
};

std::string find_exec_stub(SupportedArch arch);

std::string find_helper_library(const char* basepath);

static inline struct timeval to_timeval(double t) {
  struct timeval v;
  v.tv_sec = (time_t)floor(t);
  v.tv_usec = (int)floor((t - v.tv_sec) * 1000000);
  return v;
}

/* Slow but simple pop-count implementation. */
int pop_count(uint64_t v);

/* A version of fatal that uses no allocation/thread resource and is thus
  safe to use in volatile contexts */
void SAFE_FATAL(int err, const char *msg);

bool coredumping_signal_takes_down_entire_vm();

/* Parse tid from the proc file system path /proc/<pid>/<property> or /proc/<pid>/task/<tid>/<property> */
int parse_tid_from_proc_path(const std::string& pathname, const std::string& property);

inline unsigned long long rdtsc(void) {
#if defined(__i386__) || defined(__x86_64__)
  return __rdtsc();
#else
  FATAL() << "Reached x86-only code path on non-x86 architecture";
  return 0;
#endif
}

inline unsigned long long cntfrq(void) {
#if defined(__aarch64__)
  unsigned long long val;
  asm volatile("mrs %0, CNTFRQ_EL0" : "=r" (val));
  return val;
#else
  FATAL() << "Reached AArch64-only code path on non-AArch64 architecture";
  return 0;
#endif
}

inline unsigned long long cntvct(void) {
#if defined(__aarch64__)
  unsigned long long val;
  asm volatile("mrs %0, CNTVCT_EL0" : "=r" (val));
  return val;
#else
  FATAL() << "Reached AArch64-only code path on non-AArch64 architecture";
  return 0;
#endif
}

inline unsigned long long dczid_el0_block_size(void) {
#if defined(__aarch64__)
  unsigned long long val;
  asm volatile("mrs %0, DCZID_EL0" : "=r" (val));
  return 4ULL << (val & 0xF);
#else
  FATAL() << "Reached AArch64-only code path on non-AArch64 architecture";
  return 0;
#endif
}

/**
 * If `src` overlaps `dst`, replace the bytes in `dst_data` from the range `dst`
 * with the corresponding bytes in `src_data` from the range `src`.
 */
void replace_in_buffer(MemoryRange src, const uint8_t* src_data,
                       MemoryRange dst, uint8_t* dst_data);

// Strip any directory part from the filename `s`
void base_name(std::string& s);

std::optional<int> read_perf_event_paranoid();
char* extract_name(char* name_buffer, size_t buffer_size);

std::string default_rr_trace_dir();

std::string resolve_trace_name(const std::string& trace_name);

std::string trace_save_dir();

std::string latest_trace_symlink();

/** Convert `Registers` to data blob used in capnp */
capnp::Data::Reader regs_to_raw(const Registers&);

/** Write `ExtraRegisters` using the data from data blob reader `raw` */
void set_extra_regs_from_raw(SupportedArch arch,
                             const std::vector<CPUIDRecord>& records,
                             capnp::Data::Reader& raw, ExtraRegisters& out);

/** Convert `ExtraRegisters` to data blob used in capnp. */
capnp::Data::Reader extra_regs_to_raw(const ExtraRegisters&);

trace::Arch to_trace_arch(SupportedArch arch);
SupportedArch from_trace_arch(trace::Arch arch);

/** Convert rr's capnp string representation into std::string. */
std::string data_to_str(const kj::ArrayPtr<const capnp::byte>& data);

/** Convert std::string into rr's capnp string representation. */
kj::ArrayPtr<const capnp::byte> str_to_data(const std::string& str);

bool virtual_address_size_supported(uint8_t bit_size);

} // namespace rr

#endif /* RR_UTIL_H_ */
