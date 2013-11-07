/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef UTIL_H_
#define UTIL_H_

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#include "types.h"

struct msghdr;
struct mmsghdr;
struct task;
struct trace_frame;

#ifndef PTRACE_O_TRACESECCOMP
# define PTRACE_O_TRACESECCOMP      0x00000080 
#endif

#define GET_PTRACE_EVENT(status) \
	((0xFF0000 & status) >> 16)
#define SYSCALL_FAILED(eax) \
	(-ERANGE <= (int)(eax) && (int)(eax) < 0)
#define SYSCALL_MAY_RESTART(eax) \
	(-ERESTART_RESTARTBLOCK == (eax) || -ERESTARTNOINTR == (eax)	\
	 || -ERESTARTSYS == (eax))

/* For linux x86, as of 3.11.
 *
 * TODO: better system for this ...  */
#define MAX_SYSCALLNO 350

#define STOPSIG_SYSCALL (0x80 | SIGTRAP)

#define ALEN(_arr) (sizeof(_arr) / (sizeof(_arr[0])))

#define MAX(_a, _b) ((_a) > (_b) ? (_a) : (_b))
#define MIN(_a, _b) ((_a) < (_b) ? (_a) : (_b))

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
	/* You should probably not be using these. */
	int dev_major;
	int dev_minor;
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

char* get_inst(struct task* t, int eip_offset, int* opcode_size);
bool is_write_mem_instruction(pid_t pid, int eip_offset, int* opcode_size);
void emulate_child_inst(struct task * t, int eip_offset);
void print_inst(struct task* t);
void print_syscall(struct task *t, struct trace_frame *trace);

/**
 * Return zero if |reg1| matches |reg2|.  Passing EXPECT_MISMATCHES
 * indicates that the caller is using this as a general register
 * compare and nothing special should be done if the register files
 * mismatch.  Passing LOG_MISMATCHES will log the registers that don't
 * match.  Passing BAIL_ON_MISMATCH will additionally abort on
 * mismatch.
 */
enum { EXPECT_MISMATCHES = 0, LOG_MISMATCHES, BAIL_ON_MISMATCH };
int compare_register_files(struct task* t,
			   char* name1, const struct user_regs_struct* reg1,
			   char* name2, const struct user_regs_struct* reg2,
			   int mismatch_behavior);

void assert_child_regs_are(struct task* t, const struct user_regs_struct* regs, int event, int state);
uint64_t str2ull(const char* start, size_t max_size);
long int str2li(const char* start, size_t max_size);
void * str2x(const char* start, size_t max_size);
void read_line(FILE* file, char* buf, int size, char* name);
void add_scratch(void *ptr, int size);
void add_protected_map(struct task *t, void *start);
bool is_protected_map(struct task *t, void *start);
void add_sig_handler(pid_t tid, unsigned int signum, struct sigaction * sa);
struct sigaction * get_sig_handler(pid_t tid, unsigned int signum);

void print_register_file_tid(pid_t tid);
void print_register_file(struct user_regs_struct* regs);

/**
 * Return nonzero if the user requested memory be dumped for |t| at
 * |event| at |global_time|.
 */
int should_dump_memory(struct task* t, int event, int state, int global_time);
/**
 * Dump all of the memory in |t|'s address to the file
 * "[trace_dir]/[t->tid]_[global_time]_[tag]".
 */ 
void dump_process_memory(struct task* t, const char* tag);

/**
 * Return nonzero if the user has requested |t|'s memory be
 * checksummed at |event| at |global_time|.
 */
int should_checksum(struct task* t, int event, int state, int global_time);
/**
 * Write a checksum of each mapped region in |t|'s address space to a
 * special log, where it can be read by |validate_process_memory()|
 * during replay.
 */
void checksum_process_memory(struct task* t);
/**
 * Validate the checksum of |t|'s address space that was written
 * during recording.
 */
void validate_process_memory(struct task* t);

/**
 * Cat the /proc/[t->tid]/maps file to stdout, line by line.
 */
void print_process_mmap(struct task* t);

/**
 * Search for the segment containing |search_addr|, and if found copy
 * out the segment info to |info| and return nonzero.  Return zero if
 * not found.
 */
int find_segment_containing(struct task* t, void* search_addr,
			    struct mapped_segment_info* info);

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
int probably_not_interactive(void);

/**
 * Return nonzero if |event| is the trace event generated by the
 * syscallbuf seccomp-bpf when an traced syscall is entered.
 */
int is_ptrace_seccomp_event(int event);

/**
 * Return the symbolic name of the PTRACE_EVENT_* |event|, or
 * "???EVENT" if unknown.
 */
const char* ptrace_event_name(int event);

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

int signal_pending(int status);

/**
 * Detach |t| from rr and try hard to ensure any operations related to
 * it have completed by the time this function returns.
 */
void detach_and_reap(struct task* t);

struct current_state_buffer {
	pid_t pid;
	struct user_regs_struct regs;
	int code_size;
	long* code_buffer;
	long* start_addr;
};

void mprotect_child_region(struct task * t, void * addr, int prot);

/**
 * Copy the registers used for syscall arguments (not including
 * syscall number) from |from| to |to|.
 */
void copy_syscall_arg_regs(struct user_regs_struct* to,
			   const struct user_regs_struct* from);

/**
 * Record all the data needed to restore the |struct msghdr| pointed
 * at in |t|'s address space by |child_msghdr_ptr|.
 */
void record_struct_msghdr(struct task* t, struct msghdr* child_msghdr);
/** */
void record_struct_mmsghdr(struct task* t, struct mmsghdr* child_mmsghdr);
/**
 * Restore the recorded msghdr pointed at in |t|'s address space by
 * |child_msghdr_ptr|.
 */
void restore_struct_msghdr(struct task* t, struct msghdr* child_msghdr);
/** */
void restore_struct_mmsghdr(struct task* t, struct mmsghdr* child_mmsghdr);

/**
 * Return nonzero if |t|'s current registers |regs| indicate that
 * |t| is at an arm-desched-event or disarm-desched-event syscall.
 */
int is_desched_event_syscall(struct task* t,
			     const struct user_regs_struct* regs);
/**
 * Return nonzero if |t|'s current registers |regs| indicate that
 * |t| is at an arm-desched-event syscall.
 */
int is_arm_desched_event_syscall(struct task* t,
				 const struct user_regs_struct* regs);
/**
 * Return nonzero if |t|'s current registers |regs| indicate that
 * |t| is at a disarm-desched-event syscall.
 */
int is_disarm_desched_event_syscall(struct task* t,
				    const struct user_regs_struct* regs);

/**
 * Return nonzero if |syscallno| and |regs| look like the interrupted
 * syscall at the top of |t|'s event stack, if there is one.
 */
int is_syscall_restart(struct task* t, int syscallno,
		       const struct user_regs_struct* regs);

/**
 * Return nonzero if a mapping of |filename| with metadata |stat|,
 * using |flags| and |prot|, should almost certainly be copied to
 * trace; i.e., the file contents are likely to change in the interval
 * between recording and replay.  Zero is returned /if we think we can
 * get away/ with not copying the region.  That doesn't mean it's
 * necessarily safe to skip copying!
 */
enum { DONT_WARN_SHARED_WRITEABLE = 0, WARN_DEFAULT };
int should_copy_mmap_region(const char* filename, struct stat* stat,
			    int prot, int flags,
			    int warn_shared_writeable);

/* XXX should this go in ipc.h? */

/**
 * Prepare |t| for a series of remote syscalls.  The caller must
 * treat the outparam |state| as an immutable token while it wishes to
 * make syscalls.
 *
 * NBBB!  Before preparing for a series of remote syscalls, the caller
 * *must* ensure the callee will not receive any signals.  This code
 * does not attempt to deal with signals.
 */
void prepare_remote_syscalls(struct task* t,
			     struct current_state_buffer* state);

/**
 * Cookie used to restore stomped memory.  Users should treat these as
 * opaque and immutable.
 */
struct restore_mem {
	/* Address of tmp mem. */
	void* addr;
	/* Pointer to saved data. */
	void* data;
	/* (We keep this around for error checking.) */
	void* saved_sp;
	/* Length of tmp mem. */
	size_t len;
};
/**
 * Write |str| into |t|'s address space in such a way that the write
 * can be undone.  |t| must already have been prepared for remote
 * syscalls, in |state|.  The address of the tmp string in |t|'s
 * address space is returned.
 *
 * The cookie used to restore the stomped memory is returned in |mem|.
 * When the temporary string is no longer useful, the caller *MUST*
 * call |pop_tmp_mem()|.
 */
void* push_tmp_str(struct task* t, struct current_state_buffer* state,
		   const char* str, struct restore_mem* mem);
/**
 * Restore the memory stomped by an earlier |push_tmp_*()|.  Tmp
 * memory must be popped in the reverse order it was pushed, that is,
 * LIFO.
 */
void pop_tmp_mem(struct task* t, struct current_state_buffer* state,
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
long remote_syscall(struct task* t, struct current_state_buffer* state,
		    int wait, int syscallno,
		    long a1, long a2, long a3, long a4, long a5, long a6);
/**
 * Wait for the |DONT_WAIT| syscall |syscallno| initiated by
 * |remote_syscall()| to finish, returning the result.
 */
long wait_remote_syscall(struct task* t, struct current_state_buffer* state,
			 int syscallno);
/**
 * Undo in |t| any preparations that were made for a series of
 * remote syscalls.
 */
void finish_remote_syscalls(struct task* t,
			    struct current_state_buffer* state);

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
 * Initialize tracee buffers in |t|, i.e., implement
 * RRCALL_init_syscall_buffer.  |t| must be at the point of *exit
 * from* the rrcall.  Its registers will be updated with the return
 * value from the rrcall, which is also returned from this call.
 * |map_hint| suggests where to map the region.
 *
 * Pass SHARE_DESCHED_EVENT_FD to additionally share that fd.
 */
enum { SHARE_DESCHED_EVENT_FD = 1, DONT_SHARE_DESCHED_EVENT_FD = 0 };
void* init_buffers(struct task* t, void* map_hint, int share_desched_fd);

#endif /* UTIL_H_ */
