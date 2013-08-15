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
	USR_INIT_SCRATCH_MEM,
	USR_SYSCALLBUF_FLUSH,
	USR_SYSCALLBUF_ABORT_COMMIT,
	USR_SYSCALLBUF_RESET = -1015,
	USR_ARM_DESCHED,
	USR_DISARM_DESCHED,
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

enum {
	/* "Magic" syscalls (traps initiated by rr code running in a
	 * tracee) are negative numbers to distinguish them from real
	 * syscalls.  However, to avoid colliding with the signal
	 * "namespace" in the event encoding, they're recorded as
	 * (-syscallno | RRCALL_BIT). */
	RRCALL_BIT = 0x8000
};

/**
 * A trace_frame is one "trace event" from a complete trace.  During
 * recording, a trace_frame is recorded upon each significant event,
 * for example a context-switch or syscall.  During replay, a
 * trace_frame represents a "next state" that needs to be transitioned
 * into, and the information recorded in the frame dictates the nature
 * of the transition.
 */
struct trace_frame
{
	/* meta information */
	uint32_t global_time;
	uint32_t thread_time;
	pid_t tid;
	int stop_reason;
	int state;

	/* hpc data */
	uint64_t hw_interrupts;
	uint64_t page_faults;
	uint64_t rbc;
	uint64_t insts;

	/* register values */
	struct user_regs_struct recorded_regs;
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

char* get_trace_path(void);
void open_trace_files(struct flags rr_flags);
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
 * Recording
 */

void clear_trace_files(void);
void rec_init_trace_files(void);
void write_open_inst_dump(struct task* context);
void record_input_str(pid_t pid, int syscall, int len);
void sc_record_data(pid_t tid, int syscall, size_t len, void* buf);
void record_inst(struct task* context, char* inst);

void record_inst_done(struct task* context);
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
unsigned int get_global_time(void);
unsigned int get_time(pid_t tid);
void record_argv_envp(int argc, char* argv[], char* envp[]);
void rec_setup_trace_dir(int version);

/**
 * Replaying
 */

void init_environment(char* trace_path, int* argc, char** argv, char** envp);
void read_next_trace(struct trace_frame *trace);
void peek_next_trace(struct trace_frame *trace);
int get_trace_file_lines_counter();
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
pid_t get_recorded_main_thread();
void rep_setup_trace_dir(const char* path);

/*         function declaration for instruction dump                  */
void read_open_inst_dump(struct task* context);
char* peek_next_inst(struct task* context);
char* read_inst(struct task* context);
void inst_dump_parse_register_file(struct task* context, struct user_regs_struct* reg);
/* ------------------------------------------------------------------ */

void inst_dump_skip_entry();

struct syscall_trace
{
	uint64_t time;
	pid_t tid;
	int syscall;
	size_t data_size;
};


#endif /* TRACE_H_ */
