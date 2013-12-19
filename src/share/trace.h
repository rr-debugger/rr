/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef TRACE_H_
#define TRACE_H_

#include <signal.h>		/* for _NSIG */
#include <stdint.h>
#include <sys/stat.h>
#include <sys/user.h>

#include "types.h"

#define STATE_SYSCALL_ENTRY		  0
#define STATE_SYSCALL_EXIT		  1
#define STATE_PRE_MMAP_ACCESS     2

struct task;

enum {
	/* "Magic" (rr-generated) pseudo-signals can't be represented
	 * with a byte, as "real" signals can be.  The first is -0x400
	 * (-1024) and ascend from there. */
	SIG_SEGV_MMAP_READ = -1024,
	FIRST_RR_PSEUDOSIGNAL = SIG_SEGV_MMAP_READ,
	SIG_SEGV_MMAP_WRITE,
	SIG_SEGV_RDTSC,
	USR_EXIT,
	USR_SCHED = -1020,
	USR_NEW_RAWDATA_FILE,
	USR_SYSCALLBUF_FLUSH,
	USR_SYSCALLBUF_ABORT_COMMIT,
	USR_SYSCALLBUF_RESET,
	USR_ARM_DESCHED = -1015,
	USR_DISARM_DESCHED,
	/* Like USR_EXIT, but recorded when the task is in an
	 * "unstable" state in which we're not sure we can
	 * synchronously wait for it to "really finish". */
	USR_UNSTABLE_EXIT,
	/* TODO: this is actually a pseudo-pseudosignal: it will never
	 * appear in a trace, but is only used to communicate between
	 * different parts of the recorder code that should be
	 * refactored to not have to do that. */
	USR_NOOP,
	LAST_RR_PSEUDOSIGNAL = USR_NOOP,
	/* TODO: static_assert(LAST_RR_PSEUDOSIGNAL < FIRST_DET_SIGNAL); */

	/* Deterministic signals are recorded as -(signum | 0x80).  So
	 * these can occupy the range [-193, -128) or so. */
	DET_SIGNAL_BIT = 0x80,
	FIRST_DET_SIGNAL = -(_NSIG | DET_SIGNAL_BIT),
	LAST_DET_SIGNAL = -(1 | DET_SIGNAL_BIT),
	/* TODO: static_assert(LAST_DET_SIGNAL < FIRST_ASYNC_SIGNAL); */

	/* Asynchronously-delivered (nondeterministic) signals are
	 * recorded as -signum.  They occupy the range [-65, 0) or
	 * so. */
	FIRST_ASYNC_SIGNAL = -_NSIG,
	LAST_ASYNC_SIGNAL = -1,
};

/* Use this helper to declare a struct member that doesn't occupy
 * space, but the address of which can be taken.  Useful for
 * delimiting continugous chunks of fields without having to hard-code
 * the name of first last fields in the chunk.  (Nested structs
 * achieve the same, but at the expense of unnecessary verbosity.) */
#define STRUCT_DELIMITER(_name) char _name[0]

/**
 * A trace_frame is one "trace event" from a complete trace.  During
 * recording, a trace_frame is recorded upon each significant event,
 * for example a context-switch or syscall.  During replay, a
 * trace_frame represents a "next state" that needs to be transitioned
 * into, and the information recorded in the frame dictates the nature
 * of the transition.
 */
struct trace_frame {
	STRUCT_DELIMITER(begin_event_info);
	uint32_t global_time;
	uint32_t thread_time;
	pid_t tid;
	int stop_reason;
	int state : 31;
	int has_exec_info : 1;
	STRUCT_DELIMITER(end_event_info);

	STRUCT_DELIMITER(begin_exec_info);
	int64_t hw_interrupts;
	int64_t page_faults;
	int64_t rbc;
	int64_t insts;

	struct user_regs_struct recorded_regs;
	STRUCT_DELIMITER(end_exec_info);
};

/* XXX/pedant more accurately called a "mapped /region/", since we're
 * not mapping entire files, necessarily. */
struct mmapped_file {
	/* Global trace time when this region was mapped. */
	int time;
	int tid;
	/* Did we save a copy of the mapped region in the trace
	 * data? */
	int copied;

	char filename[1024];
	struct stat stat;

	/* Bounds of mapped region. */
	void* start;
	void* end;
};

/* These are defined by the include/linux/errno.h in the kernel tree.
 * Since userspace doesn't see these errnos in normal operation, that
 * header apparently isn't distributed with libc. */
#define ERESTARTSYS 512
#define ERESTARTNOINTR 513
#define ERESTART_RESTARTBLOCK 516

#define MAX_RAW_DATA_SIZE		(1 << 30)

const char* get_trace_path(void);
void open_trace_files(void);
void close_trace_files(void);
void flush_trace_files(void);

/**
 * Return the symbolic name of |state|, or "???state" if unknown.
 */
const char* statename(int state);

/**
 * Return a string describing |event|, or some form of "???" if
 * |event| is unknown.
 */
const char* strevent(int event);

/**
 * Log a human-readable representation of |frame| to |out|, including
 * a newline character.
 */
void dump_trace_frame(FILE* out, const struct trace_frame* frame);

/**
 * Recording
 */

void clear_trace_files(void);
void rec_init_trace_files(void);
void record_input_str(pid_t pid, int syscall, int len);
void sc_record_data(pid_t tid, int syscall, size_t len, void* buf);

void record_child_data(struct task *t, size_t len, void* child_ptr);

void record_timestamp(int tid, long int* eax_, long int* edx_);
void record_child_data_tid(pid_t tid, int event, size_t len, void* child_ptr);
void record_child_str(struct task* t, void* child_ptr);
void record_parent_data(struct task *t, size_t len, void *addr, void *buf);
/**
 * Record the current event of |t|.  Record the registers of |t|
 * (and other relevant execution state) so that it can be used or
 * verified during replay, if that state is available and meaningful
 * at |t|'s current execution point.
 */
void record_event(struct task* t);
void record_mmapped_file_stats(struct mmapped_file *file);
/**
 * Return the current global time.  This is approximately the number
 * of events that have been recorded or replayed.  It is exactly the
 * line number within the first trace file (trace_dir/trace_0) of the
 * event that was just recorded or is being replayed.
 *
 * Beware: if there are multiple trace files, this value doesn't
 * directly identify a unique file:line, by itself.
 *
 * TODO: we should either stop creating multiple files, or use an
 * interface like |const char* get_trace_file_coord()| that would
 * return a string like "trace_0:457293".
 */
unsigned int get_global_time(void);
unsigned int get_time(pid_t tid);
void record_argv_envp(int argc, char* argv[], char* envp[]);
/**
 * Create a unique directory in which all trace files will be stored.
 */
void rec_setup_trace_dir(void);

/**
 * Replaying
 */

void init_environment(char* trace_path, int* argc, char** argv, char** envp);
void read_next_trace(struct trace_frame *trace);
void peek_next_trace(struct trace_frame *trace);
void read_next_mmapped_file_stats(struct mmapped_file *file);
void peek_next_mmapped_file_stats(struct mmapped_file *file);
void rep_init_trace_files(void);
void* read_raw_data(struct trace_frame* trace, size_t* size_ptr, void** addr);
/**
 * Read the next raw-data record from the trace directly into |buf|,
 * which is of size |buf_size|, without allocating temporary storage.
 * The number of bytes written into |buf| is returned, or -1 if an
 * error occurred.  The tracee address from which this data was
 * recorded is returned in the outparam |rec_addr|.
 */
ssize_t read_raw_data_direct(struct trace_frame* trace,
			     void* buf, size_t buf_size, void** rec_addr);
/**
 * Return the tid of the first thread seen during recording.  Must be
 * called after |init_trace_files()|, and before any calls to
 * |read_next_trace()|.
 */
pid_t get_recorded_main_thread(void);
/**
 * Set the trace directory that will be replayed to |path|.
 */
void rep_setup_trace_dir(const char* path);

#endif /* TRACE_H_ */
