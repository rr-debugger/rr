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

enum {
	/* "Magic" (rr-generated) pseudo-signals can't be represented
	 * with a byte, as "real" signals can be.  The last is -0x100
	 * (-256) and ascend to there. */
	SIG_SEGV_MMAP_READ = -256,
	LAST_RR_PSEUDOSIGNAL = SIG_SEGV_MMAP_READ,
	SIG_SEGV_MMAP_WRITE = -258,
	SIG_SEGV_RDTSC = -259,
	USR_EXIT = -260,
	USR_SCHED = -261,
	USR_NEW_RAWDATA_FILE = -262,
	USR_INIT_SCRATCH_MEM = -263,
	USR_FLUSH = -264,
	FIRST_RR_PSEUDOSIGNAL = USR_FLUSH,

	/* Deterministic signals are recorded as -(signum | 0x80).  So
	 * these can occupy the range [-193, -128) or so. */
	DET_SIGNAL_BIT = 0x80,
	FIRST_DET_SIGNAL = -(_NSIG | DET_SIGNAL_BIT),
	LAST_DET_SIGNAL = -(1 | DET_SIGNAL_BIT),

	/* Asynchronously-delivered (nondeterministic) signals are
	 * recorded as -signum.  They occupy the range [-65, 0) or
	 * so. */
	FIRST_ASYNC_SIGNAL = -_NSIG,
	LAST_ASYNC_SIGNAL = -1,
};


// Notice: these are defined in errno.h if _kernel_ is defined.
#define ERESTARTNOINTR 			-513
#define ERESTART_RESTARTBLOCK	-516

#define MAX_RAW_DATA_SIZE		(1 << 30)

char* get_trace_path(void);
void open_trace_files(struct flags rr_flags);
void close_trace_files(void);
void flush_trace_files(void);

/**
 * Recording
 */

void clear_trace_files(void);
void rec_init_trace_files(void);
void write_open_inst_dump(struct context* context);
void record_input_str(pid_t pid, int syscall, int len);
void sc_record_data(pid_t tid, int syscall, size_t len, void* buf);
void record_inst(struct context* context, char* inst);

void record_inst_done(struct context* context);
void record_child_data(struct context *ctx, int syscall, size_t len, void* child_ptr);

void record_timestamp(int tid, long int* eax_, long int* edx_);
void record_child_data_tid(pid_t tid, int syscall, size_t len, void* child_ptr);
void record_child_str(pid_t tid, int syscall, void* child_ptr);
void record_parent_data(struct context *ctx, int syscall, size_t len, void *addr, void *buf);
void record_event(struct context *ctx, int state);
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
pid_t get_recorded_main_thread();
void rep_setup_trace_dir(const char* path);
void rep_child_buffer0(struct context * ctx);

/*         function declaration for instruction dump                  */
void read_open_inst_dump(struct context* context);
char* peek_next_inst(struct context* context);
char* read_inst(struct context* context);
void inst_dump_parse_register_file(struct context* context, struct user_regs_struct* reg);
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
