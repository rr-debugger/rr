#ifndef READ_TRACE_H_
#define READ_TRACE_H_

#include "replayer.h"
#include "../share/types.h"
#include "../share/trace.h"

void init_environment(char* trace_path, int* argc, char** argv, char** envp);
void read_trace_close();
void read_next_trace(struct trace* trace);
void read_trace_init(const char* trace_path);
void* read_raw_data(struct trace* trace, size_t* size_ptr, unsigned long* addr);
pid_t get_recorded_main_thread();


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

#endif /* READ_TRACE_H_ */
