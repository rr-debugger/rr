/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef UTIL_H_
#define UTIL_H_

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/user.h>

#include "types.h"
#include "../share/config.h"

#define GET_PTRACE_EVENT(status) \
	((0xFF0000 & status) >> 16)
#define SYSCALL_FAILED(eax) \
	(-ERANGE <= (int)(eax) && (int)(eax) < 0)
#define SYSCALL_WILL_RESTART(eax) \
	(ERESTART_RESTARTBLOCK == (eax) || ERESTARTNOINTR == (eax))

#ifndef PTRACE_EVENT_SECCOMP
#define PTRACE_O_TRACESECCOMP			0x00000080
#define PTRACE_EVENT_SECCOMP_OBSOLETE	8 // ubuntu 12.04
#define PTRACE_EVENT_SECCOMP			7 // ubuntu 12.10 and future kernels
#endif

#define STOPSIG_SYSCALL (0x80 | SIGTRAP)

#define ALEN(_arr) (sizeof(_arr) / (sizeof(_arr[0])))

#define MAX(_a, _b) ((_a) > (_b) ? (_a) : (_b))
#define MIN(_a, _b) ((_a) < (_b) ? (_a) : (_b))

char* get_inst(struct context* ctx, int eip_offset, int* opcode_size);
bool is_write_mem_instruction(pid_t pid, int eip_offset, int* opcode_size);
void emulate_child_inst(struct context * ctx, int eip_offset);
void print_inst(struct context* ctx);
void print_syscall(struct context *ctx, struct trace_frame *trace);
void get_eip_info(pid_t tid);
int check_if_mapped(struct context *ctx, void *start, void *end);
int compare_register_files(char* name1, const struct user_regs_struct* reg1, char* name2, const struct user_regs_struct* reg2, int print, int stop);
void assert_child_regs_are(struct context* ctx, const struct user_regs_struct* regs, int event, int state);
uint64_t str2ull(const char* start, size_t max_size);
long int str2li(const char* start, size_t max_size);
void * str2x(const char* start, size_t max_size);
void read_line(FILE* file, char* buf, int size, char* name);
void add_scratch(void *ptr, int size);
int overall_scratch_size();
void add_protected_map(struct context *ctx, void *start);
bool is_protected_map(struct context *ctx, void *start);
void add_sig_handler(pid_t tid, unsigned int signum, struct sigaction * sa);
struct sigaction * get_sig_handler(pid_t tid, unsigned int signum);

void print_register_file_tid(pid_t tid);
void print_register_file(struct user_regs_struct* regs);
void print_process_memory(struct context * ctx, char * filename);
void print_process_mmap(pid_t tid);
void checksum_process_memory(struct context * ctx);
void validate_process_memory(struct context * ctx);
void * get_mmaped_region_end(struct context * ctx, void * mmap_start);
char * get_mmaped_region_filename(struct context * ctx, void * mmap_start);
int get_memory_size(struct context * ctx);

/**
 * Get the current time from the preferred monotonic clock in units of
 * seconds, relative to an unspecific point in the past.
 */
double now_sec();

/**
 * Sleep for the duration of time specified in |ts|.  Continue
 * sleeping until |ts| has elapsed, even if a signal is received.  If
 * an error occurs, -1 is returned and errno is set appropriately.
 */
int nanosleep_nointr(const struct timespec* ts);

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


struct current_state_buffer {
	pid_t pid;
	struct user_regs_struct regs;
	int code_size;
	long* code_buffer;
	long* start_addr;
};

void inject_code(struct current_state_buffer* buf, char* code);
int inject_and_execute_syscall(struct context * ctx, struct user_regs_struct * call_regs);
void mprotect_child_region(struct context * ctx, void * addr, int prot);

/**
 * Return nonzero if |ctx|'s current registers |regs| indicate that
 * |ctx| is at an arm-desched-event or disarm-desched-event syscall.
 */
int is_desched_event_syscall(struct context* ctx,
			     const struct user_regs_struct* regs);
/**
 * Return nonzero if |ctx|'s current registers |regs| indicate that
 * |ctx| is at an arm-desched-event syscall.
 */
int is_arm_desched_event_syscall(struct context* ctx,
				 const struct user_regs_struct* regs);
/**
 * Return nonzero if |ctx|'s current registers |regs| indicate that
 * |ctx| is at a disarm-desched-event syscall.
 */
int is_disarm_desched_event_syscall(struct context* ctx,
				    const struct user_regs_struct* regs);

/* XXX should this go in ipc.h? */

/**
 * Prepare |ctx| for a series of remote syscalls.  The caller must
 * treat the outparam |state| as an immutable token while it wishes to
 * make syscalls.
 *
 * NBBB!  Before preparing for a series of remote syscalls, the caller
 * *must* ensure the callee will not receive any signals.  This code
 * does not attempt to deal with signals.
 */
void prepare_remote_syscalls(struct context* ctx,
			     struct current_state_buffer* state);
/**
 * Remotely invoke in |ctx| the specified syscall with the given
 * arguments.  The arguments must of course be valid in |ctx|, and no
 * checking of that is done by this function.
 *
 * If |wait| is |WAIT|, the syscall is finished in |ctx| and the
 * result is returned.  Otherwise if it's |DONT_WAIT|, the syscall is
 * initiated but *not* finished in |ctx|, and the return value is
 * undefined.  Call |wait_remote_syscall()| to finish the syscall and
 * get the return value.
 */
enum { WAIT = 1, DONT_WAIT = 0 };
long remote_syscall(struct context* ctx, struct current_state_buffer* state,
		    int wait, int syscallno,
		    long a1, long a2, long a3, long a4, long a5, long a6);
/**
 * Wait for the last |DONT_WAIT| syscall initiated by
 * |remote_syscall()| to finish, returning the result.
 */
long wait_remote_syscall(struct context* ctx,
			 struct current_state_buffer* state);
/**
 * Undo in |ctx| any preparations that were made for a series of
 * remote syscalls.
 */
void finish_remote_syscalls(struct context* ctx,
			    struct current_state_buffer* state);

#define remote_syscall6(_c, _s, _no, _a1, _a2, _a3, _a4, _a5, _a6)	\
	remote_syscall(_c, _s, WAIT, _no, _a1, _a2, _a3, _a4, _a5, _a6)
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
 * Initialize the syscall buffer in |ctx|, i.e., implement
 * RRCALL_init_syscall_buffer.  |ctx| must be at the point of *exit
 * from* the rrcall.  Its registers will be updated with the return
 * value from the rrcall, which is also returned from this call.
 * |map_hint| suggests where to map the region.
 *
 * Pass SHARE_DESCHED_EVENT_FD to additionally share that fd.
 *
 * XXX: this is a weird place to stick this helper
 */
enum { SHARE_DESCHED_EVENT_FD = 1, DONT_SHARE_DESCHED_EVENT_FD = 0 };
void* init_syscall_buffer(struct context* ctx, void* map_hint,
			  int share_desched_fd);

#endif /* UTIL_H_ */
