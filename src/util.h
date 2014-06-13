/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef RR_UTIL_H_
#define RR_UTIL_H_

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <unistd.h>

#include <ostream>

#include "registers.h"
#include "types.h"

struct msghdr;
struct mmsghdr;
class Task;
struct trace_frame;

#define PTRACE_EVENT_NONE 0
#define PTRACE_EVENT_STOP 128

#define PTRACE_SYSEMU 31
#define PTRACE_SYSEMU_SINGLESTEP 32

#ifndef PTRACE_O_TRACESECCOMP
# define PTRACE_O_TRACESECCOMP 0x00000080
# define PTRACE_EVENT_SECCOMP_OBSOLETE 8 // ubuntu 12.04
# define PTRACE_EVENT_SECCOMP 7	// ubuntu 12.10 and future kernels
#endif

// These are defined by the include/linux/errno.h in the kernel tree.
// Since userspace doesn't see these errnos in normal operation, that
// header apparently isn't distributed with libc.
#define ERESTARTSYS 512
#define ERESTARTNOINTR 513
#define ERESTARTNOHAND 514
#define ERESTART_RESTARTBLOCK 516

#define SYSCALL_FAILED(result) \
	(-ERANGE <= (result) && (result) < 0)
#define SYSCALL_MAY_RESTART(result) \
	(-ERESTART_RESTARTBLOCK == (result) || -ERESTARTNOINTR == (result)	\
	 || -ERESTARTNOHAND == (result) || -ERESTARTSYS == (result))

#define SHMEM_FS "/dev/shm"
#define SHMEM_FS2 "/run/shm"

/* The syscallbuf shared with tracees is created with this prefix
 * followed by the tracee tid, then immediately unlinked and shared
 * anonymously. */
#define SYSCALLBUF_SHMEM_NAME_PREFIX "rr-tracee-shmem-"
#define SYSCALLBUF_SHMEM_PATH_PREFIX SHMEM_FS "/" SYSCALLBUF_SHMEM_NAME_PREFIX

/* For linux x86, as of 3.11.
 *
 * TODO: better system for this ...  */
#define MAX_SYSCALLNO 350

#define STOPSIG_SYSCALL (0x80 | SIGTRAP)

#define ALEN(_arr) (sizeof(_arr) / (sizeof(_arr[0])))

#define MAX(_a, _b) ((_a) > (_b) ? (_a) : (_b))
#define MIN(_a, _b) ((_a) < (_b) ? (_a) : (_b))

/* The tracee doesn't open the desched event fd during replay, so it
 * can't be shared to this process.  We pretend that the tracee shared
 * this magic fd number with us and then give it a free pass for fd
 * checks that include this fd. */
#define REPLAY_DESCHED_EVENT_FD -123

#define PREFIX_FOR_EMPTY_MMAPED_REGIONS "/tmp/rr-emptyfile-"

class Task;

/**
 * Collecion of data describing a mapped memory segment, as parsed
 * from /proc/[tid]/maps on linux.
 */
struct mapped_segment_info {
	/* Name of the segment, which isn't necessarily an fs entry
	 * anywhere. */
	char name[PATH_MAX];	/* technically PATH_MAX + "deleted",
				 * but let's not go there. */
	void* start_addr;
	void* end_addr;
	int prot;
	int flags;
	int64_t file_offset;
	int64_t inode;
	int dev_major;
	int dev_minor;
};
std::ostream& operator<<(std::ostream& o, const mapped_segment_info& m);

/**
 * RAII helper to open a file and then close the fd when the helper
 * goes out of scope.
 */
class ScopedOpen {
public:
	ScopedOpen(int fd) : fd(fd) { }
	ScopedOpen(const char* pathname, int flags, mode_t mode = 0)
	    : fd(open(pathname, flags, mode)) { }
	~ScopedOpen() { close(fd); }

	operator int() const { return get(); }
	int get() const { return fd; }
private:
	int fd;
};

/**
 * Get the flags passed to rr.
 */
const struct flags* rr_flags(void);
/**
 * Exactly once, fetch a mutable reference to the structure that
 * |rr_flags()| will return, for the purposes of initialization.
 */
struct flags* rr_flags_for_init(void);

/**
 * Update the |rr_flags()| execution-target parameters to |process|
 * and |event|.  Either parameter can be < 0 to mean "don't update
 * this flag".
 */
void update_replay_target(pid_t process, int event);

/**
 * Return true if |reg1| matches |reg2|.  Passing EXPECT_MISMATCHES
 * indicates that the caller is using this as a general register
 * compare and nothing special should be done if the register files
 * mismatch.  Passing LOG_MISMATCHES will log the registers that don't
 * match.  Passing BAIL_ON_MISMATCH will additionally abort on
 * mismatch.
 */
enum { EXPECT_MISMATCHES = 0, LOG_MISMATCHES, BAIL_ON_MISMATCH };
bool compare_register_files(Task* t,
			    const char* name1,
			    const Registers* reg1,
			    const char* name2,
			    const Registers* reg2,
			    int mismatch_behavior);

void assert_child_regs_are(Task* t, const Registers* regs);

void print_register_file_tid(Task* t);
void print_register_file(const Registers* regs);

void print_register_file_compact(FILE* file, const Registers* regs);

/**
 * Create a file named |filename| and dump |buf_len| words in |buf| to
 * that file, starting with a line containing |label|.  |start_addr|
 * is the client address at which |buf| resides, if meaningful.
 * |start_addr| is used to compute the output lines of words, which
 * look like "0xValue | [0xAddr]".
 */
void dump_binary_data(const char* filename, const char* label,
		      const uint32_t* buf, size_t buf_len, void* start_addr);

/**
 * Format a suitable filename within the trace directory for dumping
 * information about |t| at the current global time, to a file that
 * contains |tag|.  The constructed filename is returned through
 * |filename|.  For example, a filename for a task with tid 12345 at
 * time 111, for a file tagged "foo", would be something like
 * "trace_0/12345_111_foo".  The returned name is not guaranteed to be
 * unique, caveat emptor.
 */
void format_dump_filename(Task* t, int global_time, const char* tag,
			  char* filename, size_t filename_size);

/**
 * Return nonzero if the user requested memory be dumped for |t| at
 * |event| at |global_time|.
 */
int should_dump_memory(Task* t, const struct trace_frame& f);
/**
 * Dump all of the memory in |t|'s address to the file
 * "[trace_dir]/[t->tid]_[global_time]_[tag]".
 */ 
void dump_process_memory(Task* t, int global_time, const char* tag);

/**
 * Return nonzero if the user has requested |t|'s memory be
 * checksummed at |event| at |global_time|.
 */
int should_checksum(Task* t, const struct trace_frame& f);
/**
 * Write a checksum of each mapped region in |t|'s address space to a
 * special log, where it can be read by |validate_process_memory()|
 * during replay.
 */
void checksum_process_memory(Task* t, int global_time);
/**
 * Validate the checksum of |t|'s address space that was written
 * during recording.
 */
void validate_process_memory(Task* t, int global_time);

/**
 * Cat the /proc/[t->tid]/maps file to stdout, line by line.
 */
void print_process_mmap(Task* t);

/**
 * The following helpers are used to iterate over a tracee's memory
 * maps.  Clients call |iterate_memory_map()|, passing an iterator
 * function that's invoked for each mapping until either the iterator
 * stops iteration by not returning CONTINUE_ITERATING, or until the
 * last mapping has been iterated over.
 *
 * For each map, a |struct map_iterator_data| object is provided which
 * contains segment info, the size of the mapping, and the raw
 * /proc/maps line the data was parsed from.
 *
 * Additionally, if clients pass the ITERATE_READ_MEMORY flag, the
 * contents of each segment are read and passed through the |mem|
 * field in the |struct map_iterator_data|.
 *
 * Any pointers passed transitively to the iterator function are
 * *owned by |iterate_memory_map()||*.  Iterator functions must copy
 * the data they wish to save beyond the scope of the iterator
 * function invocation.
 */
enum { CONTINUE_ITERATING, STOP_ITERATING };
struct map_iterator_data {
	struct mapped_segment_info info;
	/* The nominal size of the data segment. */
	ssize_t size_bytes;
	/* Pointer to data read from the segment if requested,
	 * otherwise NULL. */
	byte* mem;
	/* Length of data read from segment.  May be less than nominal
	 * segment length if an error occurs. */
	ssize_t mem_len;
	const char* raw_map_line;
};
typedef int (*memory_map_iterator_t)(void* it_data, Task* t,
				     const struct map_iterator_data* data);

typedef int (*read_segment_filter_t)(void* filt_data, Task* t,
				     const struct mapped_segment_info* info);
static const read_segment_filter_t kNeverReadSegment =
	(read_segment_filter_t)0;
static const read_segment_filter_t kAlwaysReadSegment =
	(read_segment_filter_t)1;

void iterate_memory_map(Task* t,
			memory_map_iterator_t it, void* it_data,
			read_segment_filter_t filt, void* filt_data);

/**
 * Get the current time from the preferred monotonic clock in units of
 * seconds, relative to an unspecific point in the past.
 */
double now_sec(void);

/**
 * Sleep for the duration of time specified in |ts|.  Continue
 * sleeping until |ts| has elapsed, even if a signal is received.  If
 * an error occurs, -1 is returned and errno is set appropriately.
 */
int nanosleep_nointr(const struct timespec* ts);

/**
 * Return nonzero if the rr session is probably not interactive (that
 * is, there's probably no user watching or interacting with rr), and
 * so asking for user input or other actions is probably pointless.
 */
int probably_not_interactive(int fd = STDERR_FILENO);

/**
 * If |child_fd| is a stdio fd and stdio-marking is enabled, prepend
 * the stdio write with "[rr.<global-time>]".  This allows users to
 * more easily correlate stdio with trace event numbers.
 */
void maybe_mark_stdio_write(Task* t, int child_fd);

/**
 * Return the symbolic name of the PTRACE_EVENT_* |event|, or
 * "???EVENT" if unknown.
 */
const char* ptrace_event_name(int event);

/**
 * Return the symbolic name of the PTRACE_ |request|, or "???REQ" if
 * unknown.
 */
const char* ptrace_req_name(int request);

/**
 * Return the symbolic name of |sig|, f.e. "SIGILL", or "???signal" if
 * unknown.
 */
const char* signalname(int sig);

/**
 * Return the symbolic name of |syscall|, f.e. "read", or "???syscall"
 * if unknown.
 */
const char* syscallname(int syscall);

/**
 * Return true iff replaying |syscallno| will never ever require
 * actually executing it, i.e. replay of |syscallno| is always
 * emulated.
 */
bool is_always_emulated_syscall(int syscallno);

/**
 * Convert the flags passed to the clone() syscall, |flags_arg|, into
 * the format understood by Task::clone().
 */
int clone_flags_to_task_flags(int flags_arg);

/**
 * Return the SYS_ipc sub-command (to an ipc operation) encoded in
 * |raw_cmd|.
 */
int get_ipc_command(int raw_cmd);

static const byte syscall_insn[] = { 0xcd, 0x80 };

// TODO: RAII-ify me and helpers below.
struct current_state_buffer {
	pid_t pid;
	Registers regs;
	int code_size;
	byte code_buffer[sizeof(syscall_insn)];
	void* start_addr;
};

/**
 * Return the argument rounded up to the nearest multiple of the
 * system |page_size()|.
 */
size_t ceil_page_size(size_t sz);
void* ceil_page_size(void* addr);

/**
 * Return true if the pointer or size is a multiple of the system
 * |page_size()|.
 */
bool is_page_aligned(const byte* addr);
bool is_page_aligned(size_t sz);

/** Return the system page size. */
size_t page_size();

/**
 * Copy the registers used for syscall arguments (not including
 * syscall number) from |from| to |to|.
 */
void copy_syscall_arg_regs(Registers* to,
			   const Registers* from);

/**
 * Record all the data needed to restore the |struct msghdr| pointed
 * at in |t|'s address space by |child_msghdr_ptr|.
 */
void record_struct_msghdr(Task* t, struct msghdr* child_msghdr);
/** Like record_struct_msghdr(), but records mmsghdr. */
void record_struct_mmsghdr(Task* t, struct mmsghdr* child_mmsghdr);
/**
 * Restore the recorded msghdr pointed at in |t|'s address space by
 * |child_msghdr_ptr|.
 */
void restore_struct_msghdr(Task* t, struct msghdr* child_msghdr);
/** Like restore_struct_msghdr(), but for mmsghdr. */
void restore_struct_mmsghdr(Task* t, struct mmsghdr* child_mmsghdr);

/**
 * Return true if a FUTEX_LOCK_PI operation on |futex| done by |t|
 * will transition the futex into the contended state.  (This results
 * in the kernel atomically setting the FUTEX_WAITERS bit on the futex
 * value.)  The new value of the futex after the kernel updates it is
 * returned in |next_val|.
 */
bool is_now_contended_pi_futex(Task* t, void* futex, uint32_t* next_val);

/** Return the default action of |sig|. */
enum signal_action { DUMP_CORE, TERMINATE, CONTINUE, STOP, IGNORE };
signal_action default_action(int sig);

/**
 * Return true if |sig| may cause the status of other tasks to change
 * unpredictably beyond rr's observation.
 */
bool possibly_destabilizing_signal(Task* t, int sig);

/**
 * Return nonzero if a mapping of |filename| with metadata |stat|,
 * using |flags| and |prot|, should almost certainly be copied to
 * trace; i.e., the file contents are likely to change in the interval
 * between recording and replay.  Zero is returned /if we think we can
 * get away/ with not copying the region.  That doesn't mean it's
 * necessarily safe to skip copying!
 */
enum { DONT_WARN_SHARED_WRITEABLE = 0, WARN_DEFAULT };
bool should_copy_mmap_region(const char* filename, const struct stat* stat,
			     int prot, int flags,
			     int warn_shared_writeable);

/**
 * Return an fd referring to a new shmem segment with descriptive
 * |name| of size |num_bytes|.  Pass O_NO_CLOEXEC to clo_exec to
 * prevent setting the O_CLOEXEC flag.
 */
enum { O_NO_CLOEXEC = 0 };
int create_shmem_segment(const char* name, size_t num_bytes,
			 int cloexec = O_CLOEXEC);

/**
 * Ensure that the shmem segment referred to by |fd| has exactly the
 * size |num_bytes|.
 */
void resize_shmem_segment(int fd, size_t num_bytes);

/**
 * Prepare |t| for a series of remote syscalls.  The caller must
 * treat the outparam |state| as an immutable token while it wishes to
 * make syscalls.
 *
 * NBBB!  Before preparing for a series of remote syscalls, the caller
 * *must* ensure the callee will not receive any signals.  This code
 * does not attempt to deal with signals.
 */
void prepare_remote_syscalls(Task* t, struct current_state_buffer* state);

/**
 * Cookie used to restore stomped memory.  Users should treat these as
 * opaque and immutable.
 */
struct restore_mem {
	/* Address of tmp mem. */
	void* addr;
	/* Pointer to saved data. */
	byte* data;
	/* (We keep this around for error checking.) */
	void* saved_sp;
	/* Length of tmp mem. */
	size_t len;
};

/**
 * Write |mem| into |t|'s address space in such a way that the write
 * can be undone.  |t| must already have been prepared for remote
 * syscalls, in |state|.  The address of the tmp mem in |t|'s
 * address space is returned.
 *
 * The cookie used to restore the stomped memory is returned in
 * |restore|.  When the temporary mem is no longer useful, the
 * caller *MUST* call |pop_tmp_mem()|.
 */
void* push_tmp_mem(Task* t, struct current_state_buffer* state,
		   const byte* mem, ssize_t num_bytes,
		   struct restore_mem* restore);
/**
 * Like |push_tmp_mem()|, but pushes a C string |str|, including '\0'
 * byte.
 */
void* push_tmp_str(Task* t, struct current_state_buffer* state,
		   const char* str, struct restore_mem* restore);
/**
 * Restore the memory stomped by an earlier |push_tmp_*()|.  Tmp
 * memory must be popped in the reverse order it was pushed, that is,
 * LIFO.
 */
void pop_tmp_mem(Task* t, struct current_state_buffer* state,
		 struct restore_mem* mem);

/**
 * Remotely invoke in |t| the specified syscall with the given
 * arguments.  The arguments must of course be valid in |t|, and no
 * checking of that is done by this function.
 *
 * If |wait| is |WAIT|, the syscall is finished in |t| and the
 * result is returned.  Otherwise if it's |DONT_WAIT|, the syscall is
 * initiated but *not* finished in |t|, and the return value is
 * undefined.  Call |wait_remote_syscall()| to finish the syscall and
 * get the return value.
 */
enum { WAIT = 1, DONT_WAIT = 0 };
long remote_syscall(Task* t, struct current_state_buffer* state,
		    int wait, int syscallno,
		    long a1, long a2, long a3, long a4, long a5, long a6);
/**
 * Wait for the |DONT_WAIT| syscall |syscallno| initiated by
 * |remote_syscall()| to finish, returning the result.
 */
long wait_remote_syscall(Task* t, struct current_state_buffer* state,
			 int syscallno);
/**
 * Undo in |t| any preparations that were made for a series of
 * remote syscalls.
 */
void finish_remote_syscalls(Task* t, struct current_state_buffer* state);

#define remote_syscall6(_c, _s, _no, _a1, _a2, _a3, _a4, _a5, _a6)	\
	remote_syscall(_c, _s, WAIT, _no,				\
		       (uintptr_t)(_a1), (uintptr_t)(_a2), (uintptr_t)(_a3), \
		       (uintptr_t)(_a4), (uintptr_t)(_a5), (uintptr_t)(_a6))
#define remote_syscall5(_c, _s, _no, _a1, _a2, _a3, _a4, _a5)		\
	remote_syscall6(_c, _s, _no, _a1, _a2, _a3, _a4, _a5, 0)
#define remote_syscall4(_c, _s, _no, _a1, _a2, _a3, _a4)	\
	remote_syscall5(_c, _s, _no, _a1, _a2, _a3, _a4, 0)
#define remote_syscall3(_c, _s, _no, _a1, _a2, _a3)	\
	remote_syscall4(_c, _s, _no, _a1, _a2, _a3, 0)
#define remote_syscall2(_c, _s, _no, _a1, _a2)		\
	remote_syscall3(_c, _s, _no, _a1, _a2, 0)
#define remote_syscall1(_c, _s, _no, _a1)	\
	remote_syscall2(_c, _s, _no, _a1, 0)
#define remote_syscall0(_c, _s, _no)		\
	remote_syscall1(_c, _s, _no, 0)

/**
 * At thread exit time, undo the work that init_buffers() did.
 *
 * Call this when the tracee has already entered SYS_exit. The
 * tracee will be returned at a state in which it has entered (or
 * re-entered) SYS_exit.
 */
void destroy_buffers(Task* t);

/**
 * Locate |t|'s |__kernel_vsyscall()| helper and then monkey-patch it
 * to jump to the preload lib's hook function.
 */
void monkeypatch_vdso(Task* t);

/**
 * Helper to detect when the "CPUID can cause rbcs to be lost"  bug is present.
 */
class EnvironmentBugDetector {
public:
	EnvironmentBugDetector()
		: trace_rbc_count_at_last_geteuid32(0)
		, actual_rbc_count_at_last_geteuid32(0)
		, detected_cpuid_bug(false)
	{}
	/**
	 * Call this in the context of the first spawned process to run the
	 * code that triggers the bug.
	 */
	static void run_detection_code();
	/**
	 * Call this when task t enters a traced syscall during replay.
	 */
	void notify_reached_syscall_during_replay(Task* t);
	/**
	 * Returns true when the "CPUID can cause rbcs to be lost" bug has
	 * been detected.
	 */
	bool is_cpuid_bug_detected() { return detected_cpuid_bug; }
private:
	uint64_t trace_rbc_count_at_last_geteuid32;
	uint64_t actual_rbc_count_at_last_geteuid32;
	bool detected_cpuid_bug;
};

#endif /* RR_UTIL_H_ */
