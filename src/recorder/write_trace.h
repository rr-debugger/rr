#ifndef RECORD_SC_INPUT_H_
#define RECORD_SC_INPUT_H_

#include "recorder.h"
#include "../share/types.h"

void init_trace_files(void);
void open_trace_files(void);
void close_trace_files(void);
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
void record_event(struct context* context, int new_tid);
unsigned int get_time(pid_t tid);
void record_argv_envp(int argc, char* argv[], char* envp[]);
void setup_trace_dir(int version);
#endif /* RECORD_SC_INPUT_H_ */
