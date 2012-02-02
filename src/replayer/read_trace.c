#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/user.h>

#include "read_trace.h"
#include "replayer.h"
#include "../share/sys.h"
#include "../share/util.h"
#include "../share/types.h"

static FILE *__trace;
static FILE *raw_data;
static FILE *syscall_input;
static int raw_data_file_counter = 0;

static char* trace_path = NULL;

FILE* get_trace_file()
{
	return __trace;
}

void read_open_inst_dump(struct context *ctx)
{
	char path[64];
	char tmp[32];
	strcpy(path, trace_path);
	sprintf(tmp, "/inst_dump_%d", ctx->rec_tid);
	strcat(path, tmp);
	ctx->inst_dump = sys_fopen(path, "a+");
}

void read_trace_init(const char* __trace_path)
{
	/* copy the trace path */
	assert(trace_path == NULL);
	trace_path = sys_malloc(strlen(__trace_path) + 1);
	strcpy(trace_path, __trace_path);

	char tmp[128], path[256];

	strcpy(path, __trace_path);
	strcpy(tmp, "trace");
	strcat(path, tmp);
	__trace = (FILE*) sys_fopen(path, "r");

	strcpy(path, __trace_path);
	strcpy(tmp, "syscall_input");
	strcat(path, tmp);
	syscall_input = (FILE*) sys_fopen(path, "r");

	strcpy(path, __trace_path);
	sprintf(tmp, "raw_data_%u", raw_data_file_counter++);
	strcat(path, tmp);
	raw_data = (FILE*) sys_fopen(path, "r");
	printf("path: %s\n",path);
	/* skip the first line -- is only meta-information */
	char* line = sys_malloc(1024);
	read_line(__trace, line, 1024, "trace");
	/* same for syscall_input */
	read_line(syscall_input, line, 1024, "syscall_input");
	sys_free((void**) &line);
}


void use_next_rawdata_file(void)
{
	char tmp[128], path[64];

	strcpy(path, trace_path);

	sys_fclose(raw_data);
	strcpy(path, trace_path);
	sprintf(tmp, "raw_data_%u", raw_data_file_counter++);
	strcat(path, tmp);
	raw_data = sys_fopen(path, "a+");
}


void read_trace_close(void)
{
	sys_fclose(__trace);
	sys_fclose(raw_data);
	sys_fclose(syscall_input);
}

void init_environment(char* trace_path, int* argc, char** argv, char** envp)
{
	char tmp[128], path[256];
	int i;

	strcpy(path, trace_path);
	strcpy(tmp, "/arg_env");
	strcat(path, tmp);

	FILE* arg_env = (FILE*) sys_fopen(path, "r");
	char* buf = (char*) sys_malloc(8192);

	/* the first line contains argc */
	read_line(arg_env, buf, 8192, "arg_env");
	int tmp_argc = str2li(buf, LI_COLUMN_SIZE);

	*argc = tmp_argc;

	/* followed by argv */
	for (i = 0; i < tmp_argc; i++) {
		read_line(arg_env, buf, 8192, "arg_env");
		int len = strlen(buf);
		/* overwrite the newline */
		buf[len - 1] = '\0';
		assert(len < 8192);
		strncpy(argv[i], buf, len + 1);
	}

	/* do not forget write NULL to the last element */
	argv[i] = NULL;

	/* now, read the number of environment entries */
	read_line(arg_env, buf, 8192, "arg_env");
	int envc = str2li(buf, LI_COLUMN_SIZE);

	/* followed by argv */
	for (i = 0; i < envc; i++) {
		read_line(arg_env, buf, 8192, "arg_env");
		int len = strlen(buf);
		assert(len < 8192);
		/* overwrite the newline */
		buf[len - 1] = '\0';
		strncpy(envp[i], buf, len + 1);
	}

	/* do not forget write NULL to the last element */
	envp[i] = NULL;

	/* clean up */
	sys_fclose(arg_env);
	sys_free((void**) &buf);
}

static int parse_raw_data_hdr(struct trace* trace, unsigned long* addr)
{
	char* line = sys_malloc(1024);
	read_line(syscall_input, line, 1024, "syscall_input");
	char* tmp_ptr = line;

	unsigned int time = str2li(tmp_ptr, LI_COLUMN_SIZE);
	tmp_ptr += LI_COLUMN_SIZE;
	if (time != trace->global_time) {
		errx(1, "syscall_header and trace  are out of sync: trace_file %u vs syscall_header %u\n", trace->thread_time, time);
	}

	int syscall = str2li(tmp_ptr, LI_COLUMN_SIZE);
	tmp_ptr += LI_COLUMN_SIZE;
	if (syscall != trace->stop_reason) {
		printf("global_time: %lu syscall: %d  stop_reason: %d\n", time, syscall, trace->stop_reason, time);
	}

	assert(syscall == trace->stop_reason);

	*addr = str2li(tmp_ptr, LI_COLUMN_SIZE);
	tmp_ptr += LI_COLUMN_SIZE;

	int size = str2li(tmp_ptr, LI_COLUMN_SIZE);

	sys_free((void**) &line);
	return size;
}

void* read_raw_data(struct trace* trace, size_t* size_ptr, unsigned long* addr)
{
	int size;

	size = parse_raw_data_hdr(trace, addr);
	*size_ptr = size;

	if (*addr != 0) {
		void* data = sys_malloc(size);
		int bytes_read = fread(data, 1, size, raw_data);

		if (bytes_read != size) {
			printf("read: %u   required: %u\n",bytes_read,size);
			perror("");
			sys_exit();
		}
		return data;
	}
	return NULL;
}

void read_syscall_trace(struct syscall_trace* trace)
{

	char* line = sys_malloc(1024);
	read_line(syscall_input, line, 1024, "syscall_input");
	const char* tmp_ptr = line;

	trace->time = str2li(tmp_ptr, UUL_COLUMN_SIZE);
	tmp_ptr += LI_COLUMN_SIZE;
	trace->tid = str2li(tmp_ptr, LI_COLUMN_SIZE);
	tmp_ptr += LI_COLUMN_SIZE;
	trace->syscall = str2li(tmp_ptr, LI_COLUMN_SIZE);
	tmp_ptr += LI_COLUMN_SIZE;
	trace->data_size = str2li(tmp_ptr, LI_COLUMN_SIZE);
	tmp_ptr += LI_COLUMN_SIZE;

	sys_free((void**) &line);
}

/*
 * Get the main thread if of the recorder. Note that this function must be called
 * after init_read_trace
 * @return the tid of the main thread of the recording phase
 */
pid_t get_recorded_main_thread()
{

	fpos_t pos;
	fgetpos(__trace, &pos);
	struct trace trace;
	read_next_trace(&trace);

	pid_t main_thread = trace.tid;
	fsetpos(__trace, &pos);

	return main_thread;
}

static void parse_register_file(struct user_regs_struct* regs, char* tmp_ptr)
{
	regs->eax = str2li(tmp_ptr, LI_COLUMN_SIZE);
	tmp_ptr += LI_COLUMN_SIZE;
	regs->ebx = str2li(tmp_ptr, LI_COLUMN_SIZE);
	tmp_ptr += LI_COLUMN_SIZE;
	regs->ecx = str2li(tmp_ptr, LI_COLUMN_SIZE);
	tmp_ptr += LI_COLUMN_SIZE;
	regs->edx = str2li(tmp_ptr, LI_COLUMN_SIZE);
	tmp_ptr += LI_COLUMN_SIZE;
	regs->esi = str2li(tmp_ptr, LI_COLUMN_SIZE);
	tmp_ptr += LI_COLUMN_SIZE;
	regs->edi = str2li(tmp_ptr, LI_COLUMN_SIZE);
	tmp_ptr += LI_COLUMN_SIZE;
	regs->ebp = str2li(tmp_ptr, LI_COLUMN_SIZE);
	tmp_ptr += LI_COLUMN_SIZE;
	regs->orig_eax = str2li(tmp_ptr, LI_COLUMN_SIZE);
	tmp_ptr += LI_COLUMN_SIZE;
	regs->eip = str2li(tmp_ptr, LI_COLUMN_SIZE);
	tmp_ptr += LI_COLUMN_SIZE;
	regs->eflags = str2li(tmp_ptr, LI_COLUMN_SIZE);
	tmp_ptr += LI_COLUMN_SIZE;

}

int peek_next_trace(struct trace *trace)
{
	fpos_t pos;
	fgetpos(__trace, &pos);
	int bytes_read = (int) fgets((char*)trace, sizeof(struct trace), __trace);
	/* check if read is successful */
	if (bytes_read > 0) {
		fsetpos(__trace, &pos);
		read_next_trace(trace);

	}

	fsetpos(__trace, &pos);
	return bytes_read;
}

int read_next_trace(struct trace *trace)
{
	assert(!feof(__trace));

	char *line = sys_malloc(1024);

	int bytes_read = (int) fgets(line, 1024, __trace);
	if (bytes_read <= 0) {
		return bytes_read;
	}

	char *tmp_ptr = (char*) line;

	/* read meta information */
	trace->global_time = str2li(tmp_ptr, LI_COLUMN_SIZE);
	tmp_ptr += LI_COLUMN_SIZE;
	trace->thread_time = str2li(tmp_ptr, LI_COLUMN_SIZE);
	tmp_ptr += LI_COLUMN_SIZE;
	trace->tid = str2li(tmp_ptr, LI_COLUMN_SIZE);
	tmp_ptr += LI_COLUMN_SIZE;
	trace->stop_reason = str2li(tmp_ptr, LI_COLUMN_SIZE);
	tmp_ptr += LI_COLUMN_SIZE;
	trace->state = str2li(tmp_ptr, LI_COLUMN_SIZE);
	tmp_ptr += LI_COLUMN_SIZE;

	/* no reason to read doto we do not need anymore */
	if (trace->stop_reason != 0) {

		/* read hardware performance counters */
		trace->hw_interrupts = str2ull(tmp_ptr, UUL_COLUMN_SIZE);
		tmp_ptr += UUL_COLUMN_SIZE;
		trace->page_faults = str2ull(tmp_ptr, UUL_COLUMN_SIZE);
		tmp_ptr += UUL_COLUMN_SIZE;
		trace->rbc_up = str2ull(tmp_ptr, UUL_COLUMN_SIZE);
		tmp_ptr += UUL_COLUMN_SIZE;

		//read register file
		parse_register_file(&(trace->recorded_regs), tmp_ptr);
	}
	sys_free((void**) &line);

	return bytes_read;
}

void find_in_trace(struct context *ctx, unsigned long cur_time, long int val)
{
	fpos_t pos;

	fgetpos(__trace, &pos);
	rewind(__trace);
	/* skip the header */
	char* line = sys_malloc(1024);

	read_line(__trace, line, 1024, "trace");
	struct trace trace;
	do {
		read_next_trace(&trace);
		if ((val == trace.recorded_regs.eax) || (val == trace.recorded_regs.ebx) || (val == trace.recorded_regs.ecx) || (val == trace.recorded_regs.edx) || (val == trace.recorded_regs.esi)
				|| (val == trace.recorded_regs.edi) || (val == trace.recorded_regs.ebp) || (val == trace.recorded_regs.orig_eax)) {

			printf("found val: %lx at time: %u\n", val, trace.global_time);
		}

	} while (trace.global_time < cur_time);

	sys_free((void**) &line);
	fsetpos(__trace, &pos);
}

/**
 * Gets the next instruction dump entry and increments the
 * file pointer.
 */
char* read_inst(struct context* context)
{
	char* tmp = sys_malloc(50);
	read_line(context->inst_dump, tmp, 50, "inst_dump");
	return tmp;
}

void inst_dump_parse_register_file(struct context* context, struct user_regs_struct* reg)
{
	char* tmp = sys_malloc(1024);
	read_line(context->inst_dump, tmp, 1024, "inst_dump");
	parse_register_file(reg, tmp);
	sys_free((void**) &tmp);
}

/*
 * Skips the current entry in the instruction dump. As a result the
 * file pointer points to the beginning of the next entry.
 */
void inst_dump_skip_entry(struct context* context)
{
	char* tmp = sys_malloc(1024);
	read_line(context->inst_dump, tmp, 1024, "inst_dump");
	read_line(context->inst_dump, tmp, 1024, "inst_dump");
	sys_free((void**) &tmp);
}

/**
 * Gets the next instruction dump entry but does NOT increment
 * the file pointer.
 */
char* peek_next_inst(struct context* context)
{
	char* tmp = sys_malloc(1024);
	fpos_t pos;
	fgetpos(context->inst_dump, &pos);
	read_line(context->inst_dump, tmp, 1024, "inst_dump");
	fsetpos(context->inst_dump, &pos);
	return tmp;
}
