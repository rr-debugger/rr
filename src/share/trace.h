#ifndef TRACE_H_
#define TRACE_H_

#include <stdint.h>
#include <sys/user.h>
#include <sys/stat.h>

#include "types.h"


#define STATE_SYSCALL_ENTRY		  0
#define STATE_SYSCALL_EXIT		  1
#define STATE_PRE_MMAP_ACCESS     2

#define SIG_SEGV_MMAP_READ		-126
#define SIG_SEGV_MMAP_WRITE		-127
#define SIG_SEGV_RDTSC 			-128
#define USR_EXIT				-129
#define USR_SCHED				-130
#define USR_NEW_RAWDATA_FILE	-131
#define USR_INIT_SCRATCH_MEM	-132
#define USR_FLUSH				-133

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
void record_child_data(struct context *ctx, int syscall, size_t len, long int child_ptr);

void record_timestamp(int tid, long int* eax_, long int* edx_);
void record_child_data_tid(pid_t tid, int syscall, size_t len, long int child_ptr);
void record_child_str(pid_t tid, int syscall, long int child_ptr);
void record_parent_data(struct context *ctx, int syscall, int len, void *addr, void *buf);
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
void read_next_trace(struct trace *trace);
void peek_next_trace(struct trace *trace);
void read_next_mmapped_file_stats(struct mmapped_file *file);
void peek_next_mmapped_file_stats(struct mmapped_file *file);
void rep_init_trace_files(void);
void* read_raw_data(struct trace* trace, size_t* size_ptr, unsigned long* addr);
pid_t get_recorded_main_thread();
void rep_setup_trace_dir(const char* path);

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
