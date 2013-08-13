/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <assert.h>
#include <err.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/user.h>
#include <sys/syscall.h>

#include "config.h"
#include "dbg.h"
#include "hpc.h"
#include "ipc.h"
#include "sys.h"
#include "syscall_buffer.h"
#include "task.h"
#include "trace.h"
#include "util.h"

#define BUF_SIZE 1024;
#define LINE_SIZE 50;

static char* trace_path_ = NULL;

static FILE *syscall_header;
static FILE *raw_data;
static FILE *trace_file;
static FILE *mmaps_file;

static int raw_data_file_counter = 0;
static uint32_t trace_file_counter = 0;
static uint32_t trace_file_lines_counter = 0;
static uint32_t thread_time[100000];
static uint32_t global_time = 0;

static struct flags rr_flags_ = {0};

// counts the number of raw bytes written, a new raw_data file is used when MAX_RAW_DATA_SIZE is reached
static long long overall_raw_bytes = 0;

void flush_trace_files(void) {
	fflush(syscall_header);
	fflush(raw_data);
	fflush(trace_file);
	fflush(mmaps_file);
}

char* get_trace_path() {
	return trace_path_;
}

const char* statename(int state)
{
	switch (state) {
#define CASE(_id) case _id: return #_id
	CASE(STATE_SYSCALL_ENTRY);
	CASE(STATE_SYSCALL_EXIT);
	CASE(STATE_PRE_MMAP_ACCESS);
#undef CASE

	default:
		return "???state";
	}
}

static const char* decode_signal_event(int sig)
{
	int det;
	static __thread char buf[] =
		"SIGREALLYREALLYLONGNAME(asynchronouslydelivered)";

	if (FIRST_RR_PSEUDOSIGNAL <= sig && sig <= LAST_RR_PSEUDOSIGNAL) {
		switch (sig) {
#define CASE(_id) case _id: return #_id
		CASE(SIG_SEGV_MMAP_READ);
		CASE(SIG_SEGV_MMAP_WRITE);
		CASE(SIG_SEGV_RDTSC);
		CASE(USR_EXIT);
		CASE(USR_SCHED);
		CASE(USR_NEW_RAWDATA_FILE);
		CASE(USR_INIT_SCRATCH_MEM);
		CASE(USR_SYSCALLBUF_FLUSH);
		CASE(USR_SYSCALLBUF_ABORT_COMMIT);
		CASE(USR_SYSCALLBUF_RESET);
		CASE(USR_ARM_DESCHED);
		CASE(USR_DISARM_DESCHED);
		CASE(USR_NOOP);
#undef CASE
		}
	}

	if (sig < FIRST_DET_SIGNAL) {
		return "???pseudosignal";
	}

	sig = -sig;
	det = sig & DET_SIGNAL_BIT;
	sig &= ~DET_SIGNAL_BIT;

	snprintf(buf, sizeof(buf) - 1, "%s(%s)",
		 signalname(sig), det ? "det" : "async");
	return buf;
}

const char* strevent(int event)
{
	if (0 > event) {
		return decode_signal_event(event);
	}
	if (0 < event) {
		return syscallname(event);
	}
	return "???event";
}

/**
 * Return the encoded event number of |ev| that's suitable for saving
 * to trace.  |state| is set to the corresponding execution state.
 */
static int encode_event(struct event* ev, int* state)
{
	switch (ev->type) {
	case EV_PSEUDOSIG:
		/* (Arbitrary.) */
		*state = STATE_SYSCALL_ENTRY;
		switch (ev->pseudosig.no) {
			/* TODO: unify these definitions. */
#define TRANSLATE(_e) case E ##_e: return _e
			TRANSLATE(SIG_SEGV_MMAP_READ);
			TRANSLATE(SIG_SEGV_MMAP_WRITE);
			TRANSLATE(SIG_SEGV_RDTSC);
			TRANSLATE(USR_EXIT);
			TRANSLATE(USR_SCHED);
			TRANSLATE(USR_NEW_RAWDATA_FILE);
			TRANSLATE(USR_INIT_SCRATCH_MEM);
			TRANSLATE(USR_SYSCALLBUF_FLUSH);
			TRANSLATE(USR_SYSCALLBUF_ABORT_COMMIT);
			TRANSLATE(USR_SYSCALLBUF_RESET);
			TRANSLATE(USR_ARM_DESCHED);
			TRANSLATE(USR_DISARM_DESCHED);
		default:
			fatal("Unknown pseudosig %d", ev->pseudosig.no);
#undef TRANSLATE
		}

	case EV_SIGNAL: {
		int event = ev->signal.no;
		/* (Arbitrary.) */
		*state = STATE_SYSCALL_ENTRY;
		if (ev->signal.deterministic) {
			event |= DET_SIGNAL_BIT;
		}
		return -event;
	}

	case EV_SYSCALL: {
		int event = ev->syscall.no;

		assert(ev->syscall.state != PROCESSING_SYSCALL);

		if (RRCALL_init_syscall_buffer == event) {
			event = (-event | RRCALL_BIT);
		}
		*state = (ev->syscall.state == ENTERING_SYSCALL) ?
			 STATE_SYSCALL_ENTRY : STATE_SYSCALL_EXIT;
		return event;
	}

	default:
		fatal("Unknown event type %d", ev->type);
		return -(1 << 30); /* not reached */
	}
}

void write_open_inst_dump(struct context *ctx)
{
	char path[64];
	char tmp[32];
	strcpy(path, trace_path_);
	sprintf(tmp, "/inst_dump_%d", ctx->tid);
	strcat(path, tmp);
	ctx->inst_dump = sys_fopen(path, "a+");
}

static unsigned int get_global_time_incr()
{
	return global_time++;
}

unsigned int get_global_time()
{
	return global_time;
}

static unsigned int get_time_incr(pid_t tid)
{
	return thread_time[tid]++;
}

unsigned int get_time(pid_t tid)
{
	return thread_time[tid];
}

/**
 * sets up the directory where all trace files will be stored. If the trace
 * file already exists, the version number is increased
 */
void rec_setup_trace_dir(int version)
{
	char ver[32], path[PATH_MAX];
	const char* output_dir;
	/* convert int to char* */
	sprintf(ver, "_%d", version);
	if (!(output_dir = getenv("_RR_TRACE_DIR"))) {
		output_dir = ".";
	}
	strcpy(path, output_dir);
	strcat(path, "/trace");

	const char* tmp_path = strcat(path, ver);

	if (mkdir(tmp_path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) == -1) {
		int error = errno;
		if (error == EEXIST) {
			rec_setup_trace_dir(version + 1);
		}
	} else {
		trace_path_ = sys_malloc(strlen(tmp_path) + 1);
		strcpy(trace_path_, tmp_path);
		log_info("Saving trace files to %s", trace_path_);
	}
}

void record_argv_envp(int argc, char* argv[], char* envp[])
{

	char tmp[128], path[64];
	int i, j;
	/* construct path to file */
	strcpy(path, trace_path_);
	strcpy(tmp, "/arg_env");
	strcat(path, tmp);

	FILE* arg_env = (FILE*) sys_fopen(path, "a+");

	/* print argc */
	fprintf(arg_env, "%d\n", argc);

	/* print arguments to file */
	for (i = 0; i < argc; i++) {
		fprintf(arg_env, "%s\n", argv[i]);
	}

	/* figure out the length of envp */
	i = 0;
	while (envp[i] != NULL) {
		i++;
	}
	fprintf(arg_env, "%d\n", i);

	for (j = 0; j < i; j++) {
		fprintf(arg_env, "%s\n", envp[j]);
	}
	sys_fclose(arg_env);
}

void open_trace_files(struct flags rr_flags)
{
	rr_flags_ = rr_flags;
	char tmp[128], path[128];

	strcpy(path, trace_path_);
	sprintf(tmp, "/trace_%u", trace_file_counter);
	strcat(path, tmp);
	trace_file = sys_fopen(path, "a+");

	strcpy(path, trace_path_);
	strcpy(tmp, "/syscall_input");
	strcat(path, tmp);
	syscall_header = sys_fopen(path, "a+");

	strcpy(path, trace_path_);
	sprintf(tmp, "/raw_data_%u", raw_data_file_counter);
	strcat(path, tmp);
	raw_data = sys_fopen(path, "a+");

	strcpy(path, trace_path_);
	strcpy(tmp, "/mmaps");
	strcat(path, tmp);
	mmaps_file = sys_fopen(path, "a+");

}

static void use_new_rawdata_file(void)
{
	char tmp[128], path[64];
	sys_fclose(raw_data);
	overall_raw_bytes = 0;
	strcpy(path, trace_path_);
	sprintf(tmp, "/raw_data_%u", ++raw_data_file_counter);
	strcat(path, tmp);
	raw_data = sys_fopen(path, "a+");
}

static void use_new_trace_file(void)
{
	char tmp[128], path[64];

	sys_fclose(trace_file);
	strcpy(path, trace_path_);
	sprintf(tmp, "/trace_%u", ++trace_file_counter);
	strcat(path, tmp);
	trace_file = sys_fopen(path, "a+");
}

void rec_init_trace_files(void)
{
	/* init trace file */
	fprintf(trace_file, "%11s", "global_time");
	fprintf(trace_file, "%11s", "thread_time");
	fprintf(trace_file, "%11s", "tid");
	fprintf(trace_file, "%11s", "reason");
	fprintf(trace_file, "%11s", "entry/exit");
	fprintf(trace_file, "%20s", "hw_interrupts");
	fprintf(trace_file, "%20s", "page_faults");
	fprintf(trace_file, "%20s", "adapted_rbc");
	fprintf(trace_file, "%20s", "instructions");

	fprintf(trace_file, "%11s", "eax");
	fprintf(trace_file, "%11s", "ebx");
	fprintf(trace_file, "%11s", "ecx");
	fprintf(trace_file, "%11s", "edx");
	fprintf(trace_file, "%11s", "esi");
	fprintf(trace_file, "%11s", "edi");
	fprintf(trace_file, "%11s", "ebp");
	fprintf(trace_file, "%11s", "orig_eax");
	fprintf(trace_file, "%11s", "esp");
	fprintf(trace_file, "%11s", "eip");
	fprintf(trace_file, "%11s", "eflags");
	fprintf(trace_file, "\n");

	/* print human readable header */
	fprintf(syscall_header, "%11s", "time");
	fprintf(syscall_header, "%11s", "syscall");
	fprintf(syscall_header, "%11s", "addr");
	fprintf(syscall_header, "%11s\n", "size");


	fprintf(mmaps_file, "%11s", "time");
	fprintf(mmaps_file, "%11s", "tid");
	fprintf(mmaps_file, "%11s", "mmap_start");
	fprintf(mmaps_file, "%11s", "mmap_end");
	fprintf(mmaps_file, "%11s", "blksize");
	fprintf(mmaps_file, "%11s", "blocks");
	fprintf(mmaps_file, "%11s", "ctim.sec");
	fprintf(mmaps_file, "%11s", "ctim.nsec");
	fprintf(mmaps_file, "%11s", "dev");
	fprintf(mmaps_file, "%11s", "gid");
	fprintf(mmaps_file, "%11s", "ino");
	fprintf(mmaps_file, "%11s", "mode");
	fprintf(mmaps_file, "%11s", "mtim.sec");
	fprintf(mmaps_file, "%11s", "mtim.nsec");
	fprintf(mmaps_file, "%11s", "rdev");
	fprintf(mmaps_file, "%11s", "size");
	fprintf(mmaps_file, "%11s", "uid");
	fprintf(mmaps_file, "%11s\n", "filename");

	fflush(mmaps_file);
	fflush(trace_file);
	fflush(syscall_header);
	fflush(raw_data);

}

void close_trace_files(void)
{
	// the files might not have been open at all
	if (syscall_header)
		sys_fclose(syscall_header);
	if (raw_data)
		sys_fclose(raw_data);
	if (trace_file)
		sys_fclose(trace_file);
	if (mmaps_file)
		sys_fclose(mmaps_file);
}

static void record_performance_data(struct context *ctx)
{
	fprintf(trace_file, "%20llu", read_hw_int(ctx->hpc));
	fprintf(trace_file, "%20llu", read_page_faults(ctx->hpc));
	fprintf(trace_file, "%20llu", read_rbc(ctx->hpc));
	fprintf(trace_file, "%20llu", read_insts(ctx->hpc));
}

static void record_register_file(struct context *ctx)
{
	pid_t tid = ctx->tid;
	struct user_regs_struct regs;
	read_child_registers(tid, &regs);

	fprintf(trace_file, "%11lu", regs.eax);
	fprintf(trace_file, "%11lu", regs.ebx);
	fprintf(trace_file, "%11lu", regs.ecx);
	fprintf(trace_file, "%11lu", regs.edx);
	fprintf(trace_file, "%11lu", regs.esi);
	fprintf(trace_file, "%11lu", regs.edi);
	fprintf(trace_file, "%11lu", regs.ebp);
	fprintf(trace_file, "%11lu", regs.orig_eax);
	fprintf(trace_file, "%11lx", regs.esp);
	fprintf(trace_file, "%11lx", regs.eip);
	fprintf(trace_file, "%11lu", regs.eflags);
}

static void record_inst_register_file(struct context *ctx)
{

	pid_t tid = ctx->tid;
	struct user_regs_struct regs;
	read_child_registers(tid, &regs);

	fprintf(ctx->inst_dump, "%11lu", regs.eax);
	fprintf(ctx->inst_dump, "%11lu", regs.ebx);
	fprintf(ctx->inst_dump, "%11lu", regs.ecx);
	fprintf(ctx->inst_dump, "%11lu", regs.edx);
	fprintf(ctx->inst_dump, "%11lu", regs.esi);
	fprintf(ctx->inst_dump, "%11lu", regs.edi);
	fprintf(ctx->inst_dump, "%11lu", regs.ebp);
	fprintf(ctx->inst_dump, "%11lu", regs.orig_eax);
	fprintf(ctx->inst_dump, "%11lx", regs.esp);
	fprintf(ctx->inst_dump, "%11lx", regs.eip);
	fprintf(ctx->inst_dump, "%11lu", regs.eflags);
	fprintf(ctx->inst_dump, "\n");
}
/**
 * Flush the syscallbuf to the trace, if there are any pending entries.
 */
static void maybe_flush_syscallbuf(struct context *ctx)
{
	if (!ctx || !ctx->syscallbuf_hdr
	    || 0 == ctx->syscallbuf_hdr->num_rec_bytes) {
		/* No context, no syscallbuf, or no records.  Nothing
		 * to do. */
		return;
	}
	/* Write the entire buffer in one shot without parsing it,
	 * since replay will take care of that. */
	push_pseudosig(ctx, EUSR_SYSCALLBUF_FLUSH, NO_EXEC_INFO);
	record_parent_data(ctx,
			   /* Record the header for consistency checking. */
			   ctx->syscallbuf_hdr->num_rec_bytes + sizeof(*ctx->syscallbuf_hdr),
			   ctx->syscallbuf_child, ctx->syscallbuf_hdr);
	record_event(ctx);
	pop_pseudosig(ctx);

	/* Reset header. */
	assert(!ctx->syscallbuf_hdr->abort_commit);
	memset(ctx->syscallbuf_hdr, 0, sizeof(*ctx->syscallbuf_hdr));
	ctx->flushed_syscallbuf = 1;
}

/**
 * Makes an entry into the event trace file
 */
void record_event(struct context *ctx)
{
	struct event* ev = ctx->ev;
	int state;
	int event = encode_event(ev, &state);

	if (USR_SYSCALLBUF_FLUSH != event) {
		// before anything is performed, check if the seccomp record cache has any entries
		maybe_flush_syscallbuf(ctx);
	}

	if (((global_time % MAX_TRACE_ENTRY_SIZE) == 0) && (global_time > 0)) {
		use_new_trace_file();
	}

	if (rr_flags_.dump_on == ctx->event
	    || rr_flags_.dump_on == DUMP_ON_ALL
	    || rr_flags_.dump_at == global_time) {
		char pid_str[PATH_MAX];
		sprintf(pid_str,"%s/%d_%d_rec",get_trace_path(),ctx->tid,get_global_time());
		print_process_memory(ctx,pid_str);
	}

	// do memory checksum
	if (((rr_flags_.checksum == CHECKSUM_ALL) ||
		 (rr_flags_.checksum == CHECKSUM_SYSCALL && state == STATE_SYSCALL_EXIT) ||
		 (rr_flags_.checksum <= global_time) )
		 && ctx)
		checksum_process_memory(ctx);

	fprintf(trace_file, "%11d%11u%11d%11d", get_global_time_incr(),
	        get_time_incr(ctx->tid), ctx->tid, event);

	debug("trace: %11d%11u%11d%11d%11d", get_global_time(),
	      get_time(ctx->tid), ctx->tid, event,
	      state);

	if (EV_PSEUDOSIG != ev->type || ev->pseudosig.has_exec_info) {
		fprintf(trace_file, "%11d", state);

		record_performance_data(ctx);
		record_register_file(ctx);
		reset_hpc(ctx, rr_flags_.max_rbc);
	}
	fprintf(trace_file, "\n");
}

static void print_header(int syscallno, void* addr)
{
	fprintf(syscall_header, "%11u", global_time);
	fprintf(syscall_header, "%11d", syscallno);
	fprintf(syscall_header, "%11u", (uintptr_t)addr);
}

/**
 * Writes data into the raw_data file and generates a corresponding entry in
 * syscall_input.
 */
void record_child_data_tid(pid_t tid, int syscall, size_t len, void* child_ptr)
{
	assert(len >= 0);
	print_header(syscall, child_ptr);
	fprintf(syscall_header, "%11d\n", len);
	//debug("Asking to write %d bytes from %p", len, child_ptr);
	if (child_ptr != 0) {
		void* buf = read_child_data_tid(tid, len, child_ptr);
		/* ensure that everything is written */
		int bytes_written = fwrite(buf, 1, len, raw_data);
		(void)bytes_written;
		assert(bytes_written == len);
		overall_raw_bytes += len;
		sys_free((void**) &buf);
	}
	//debug("Overall bytes = %d", overall_bytes);

	// new raw data file
	if (overall_raw_bytes > MAX_RAW_DATA_SIZE)
		use_new_rawdata_file();
}

static void write_raw_data(struct context *ctx, void *buf, size_t to_write)
{
	size_t bytes_written;
	(void)bytes_written;
	//debug("Asking to write %d bytes from %p", to_write, buf);

	/*
	if (overall_bytes % 10000 == 0)
	{
		struct context safe_ctx;
		memcpy(&safe_ctx, ctx, sizeof(struct context));
		ctx->event = USR_NEW_RAWDATA_FILE;
		record_event(ctx, STATE_SYSCALL_ENTRY);
		memcpy(ctx, &safe_ctx, sizeof(struct context));
		use_new_rawdata_file();
		assert(fwrite(buf, 1, to_write, raw_data) == to_write);
	}
	*/

	bytes_written = fwrite(buf, 1, to_write, raw_data);
	assert(bytes_written == to_write);

	/*
	if ((bytes_written = fwrite(buf, 1, to_write, raw_data)) != to_write) {
		struct context safe_ctx;
		memcpy(&safe_ctx, ctx, sizeof(struct context));
		ctx->event = USR_NEW_RAWDATA_FILE;
		record_event(ctx, STATE_SYSCALL_ENTRY);
		memcpy(ctx, &safe_ctx, sizeof(struct context));
		use_new_rawdata_file();
		bytes_written = fwrite(buf, 1, to_write, raw_data);
		assert(bytes_written == to_write);
	}
	*/
	overall_raw_bytes += to_write;
	//debug("Overall bytes = %d", overall_bytes);

	// new raw data file
	if (overall_raw_bytes > MAX_RAW_DATA_SIZE)
		use_new_rawdata_file();
}

/**
 * Writes data into the raw_data file and generates a corresponding entry in
 * syscall_input.
 */

#define SMALL_READ_SIZE	4096
static char read_buffer[SMALL_READ_SIZE];

void record_child_data(struct context *ctx, size_t size, void* child_ptr)
{
	int state;
	int event = encode_event(ctx->ev, &state);
	ssize_t read_bytes;
	(void)state;

	/* We shouldn't be recording a scratch address */
	assert(child_ptr != ctx->scratch_ptr);

	// before anything is performed, check if the seccomp record cache has any entries
	maybe_flush_syscallbuf(ctx);

	/* ensure world-alignment and size of loads -- that's more efficient in the replayer */
	if (child_ptr != 0) {
		if (size <= SMALL_READ_SIZE) {
			read_child_usr(ctx, read_buffer, child_ptr, size);
			write_raw_data(ctx, read_buffer, size);
			read_bytes = size;
		} else {
			//debug("Asking to record %d bytes from %p",size,child_ptr);
			void* buf = read_child_data_checked(ctx, size, child_ptr, &read_bytes);
			//debug("Read from child %d bytes", read_bytes);
			if (read_bytes == -1) {
				log_warn("Can't read from child %d memory at %p, time = %d",ctx->tid,child_ptr, get_global_time());
				getchar();
				//buf = sys_malloc(size)
				//read_child_buffer(ctx->tid,child_ptr,size,buf);
				write_raw_data(ctx, buf, 0);
				read_bytes = 0;
			} else {
				/* ensure that everything is written */
				if (read_bytes != size /*&& read_child_orig_eax(ctx->tid) != 192*/) {
					log_err("bytes_read: %x  len %x   syscall: %ld\n", read_bytes, size, read_child_orig_eax(ctx->tid));
					print_register_file_tid(ctx->tid);
					assert(1==0);
				}
				write_raw_data(ctx, buf, read_bytes);
			}
			sys_free((void**) &buf);
		}
	} else {
		read_bytes = size = 0;
	}
	assert(read_bytes == size);
	print_header(event, child_ptr);
	fprintf(syscall_header, "%11d\n", read_bytes);
}

void record_parent_data(struct context *ctx, size_t len, void *addr, void *buf)
{
	int state;
	int event = encode_event(ctx->ev, &state);
	(void)state;

	/* We shouldn't be recording a scratch address */
	assert(addr != ctx->scratch_ptr);

	write_raw_data(ctx, buf, len);
	print_header(event, addr);
	assert(len >= 0);
	fprintf(syscall_header, "%11d\n", len);
}

void record_mmapped_file_stats(struct mmapped_file *file)
{
	/* XXX this could be faster ... */
	fprintf(mmaps_file, "%11d", file->time);
	fprintf(mmaps_file, "%11d", file->tid);
	fprintf(mmaps_file, "%11d", file->copied);
	fprintf(mmaps_file, "%11x", (uintptr_t)file->start);
	fprintf(mmaps_file, "%11x", (uintptr_t)file->end);
	fprintf(mmaps_file, "%11lu", file->stat.st_blksize);
	fprintf(mmaps_file, "%11lu", file->stat.st_blocks);
	fprintf(mmaps_file, "%11lu", file->stat.st_ctim.tv_sec);
	fprintf(mmaps_file, "%11lu", file->stat.st_ctim.tv_nsec);
	fprintf(mmaps_file, "%11llu", file->stat.st_dev);
	fprintf(mmaps_file, "%11u", file->stat.st_gid);
	fprintf(mmaps_file, "%11lu", file->stat.st_ino);
	fprintf(mmaps_file, "%11u", file->stat.st_mode);
	fprintf(mmaps_file, "%11lu", file->stat.st_mtim.tv_sec);
	fprintf(mmaps_file, "%11lu", file->stat.st_mtim.tv_nsec);
	fprintf(mmaps_file, "%11llu", file->stat.st_rdev);
	fprintf(mmaps_file, "%11lu", file->stat.st_size);
	fprintf(mmaps_file, "%11d", file->stat.st_uid);
	fprintf(mmaps_file, "%s\n", file->filename);
}

void record_child_str(struct context* ctx, void* child_ptr)
{
	pid_t tid = ctx->tid;
	int state;
	int event = encode_event(ctx->ev, &state);
	(void)state;

	print_header(event, child_ptr);
	char* buf = read_child_str(tid, child_ptr);
	size_t len = strlen(buf) + 1;
	fprintf(syscall_header, "%11d\n", len);
	int bytes_written = fwrite(buf, 1, len, raw_data);
	(void)bytes_written;
	overall_raw_bytes += len;

	assert(bytes_written == len);
	sys_free((void**) &buf);

	// new raw data file
	if (overall_raw_bytes > MAX_RAW_DATA_SIZE)
		use_new_rawdata_file();

}

void record_inst(struct context *ctx, char* inst)
{
	fprintf(ctx->inst_dump, "%d:%-40s\n", ctx->tid, inst);
	record_inst_register_file(ctx);
}

void record_inst_done(struct context* context)
{
	fprintf(context->inst_dump, "%s\n", "__done__");
}


FILE* get_trace_file()
{
	return trace_file;
}

void read_open_inst_dump(struct context *ctx)
{
	char path[64];
	char tmp[32];
	strcpy(path, trace_path_);
	sprintf(tmp, "/inst_dump_%d", ctx->rec_tid);
	strcat(path, tmp);
	ctx->inst_dump = sys_fopen(path, "a+");
}


void rep_setup_trace_dir(const char * path) {
	/* XXX is it really ok to do this? */
	trace_path_ = (char*)path;
}

void rep_init_trace_files(void)
{
	/* skip the first line -- is only meta-information */
	char* line = sys_malloc(1024);
	read_line(trace_file, line, 1024, "trace");
	++trace_file_lines_counter;
	/* same for syscall_input */
	read_line(syscall_header, line, 1024, "syscall_input");
	/* same for timestamps */
	read_line(mmaps_file, line, 1024, "stats");
	sys_free((void**) &line);

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

static size_t parse_raw_data_hdr(struct trace_frame* trace, void** addr)
{
	/* XXX rewrite me */
	char* line = sys_malloc(1024);
	char* tmp_ptr;
	int time, syscall, size;

	read_line(syscall_header, line, 1024, "syscall_input");
	tmp_ptr = line;

	time = str2li(tmp_ptr, LI_COLUMN_SIZE);
	tmp_ptr += LI_COLUMN_SIZE;
	syscall = str2li(tmp_ptr, LI_COLUMN_SIZE);
	tmp_ptr += LI_COLUMN_SIZE;
	*addr = (void*)str2li(tmp_ptr, LI_COLUMN_SIZE);
	tmp_ptr += LI_COLUMN_SIZE;
	size = str2li(tmp_ptr, LI_COLUMN_SIZE);

	if (time != trace->global_time
	    || (trace->stop_reason != SYS_restart_syscall
		&& syscall != trace->stop_reason)) {
		fatal("trace and syscall_input out of sync: trace is at (time=%d, %s), but input is for (time=%d, %s)",
		      trace->global_time, strevent(trace->stop_reason),
		      time, strevent(syscall));
	}
	sys_free((void**) &line);
	return size;
}

/**
 * Read |num_bytes| from the current rawdata file into |buf|, which
 * the caller must ensure is sized appropriately.  Skip to next
 * rawdata file if the current one is at eof.
 */
static void read_rawdata(void* buf, size_t num_bytes)
{
	size_t bytes_read = fread(buf, 1, num_bytes, raw_data);

	// new raw data file
	//if (overall_raw_bytes > MAX_RAW_DATA_SIZE)
	if (bytes_read == 0 && feof(raw_data)) {
		use_new_rawdata_file();
		bytes_read = fread(buf, 1, num_bytes, raw_data);
	}
	if (bytes_read != num_bytes) {
		fatal("rawdata read of %u requested, but %u read",
		      num_bytes, bytes_read);
	}
	overall_raw_bytes += bytes_read;
}

void* read_raw_data(struct trace_frame* trace, size_t* size_ptr, void** addr)
{
	size_t size = parse_raw_data_hdr(trace, addr);
	void* data = NULL;

	*size_ptr = size;
	if (!*addr) {
		return NULL;
	}

	data = sys_malloc(size);
	read_rawdata(data, size);
	return data;
}

ssize_t read_raw_data_direct(struct trace_frame* trace,
			     void* buf, size_t buf_size, void** rec_addr)
{
	size_t data_size = parse_raw_data_hdr(trace, rec_addr);

	if (!*rec_addr) {
		return 0;
	}

	assert(data_size <= buf_size);
	read_rawdata(buf, data_size);
	return data_size;
}

void read_syscall_trace(struct syscall_trace* trace)
{

	char* line = sys_malloc(1024);
	read_line(syscall_header, line, 1024, "syscall_input");
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
	fgetpos(trace_file, &pos);
	int saved_trace_file_lines_counter = trace_file_lines_counter;
	struct trace_frame trace;
	read_next_trace(&trace);

	pid_t main_thread = trace.tid;
	fsetpos(trace_file, &pos);
	trace_file_lines_counter = saved_trace_file_lines_counter;

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
	regs->esp = (uintptr_t)str2x(tmp_ptr, LI_COLUMN_SIZE);
	tmp_ptr += LI_COLUMN_SIZE;
	regs->eip = (uintptr_t)str2x(tmp_ptr, LI_COLUMN_SIZE);
	tmp_ptr += LI_COLUMN_SIZE;
	regs->eflags = str2li(tmp_ptr, LI_COLUMN_SIZE);
	tmp_ptr += LI_COLUMN_SIZE;

}

/**
 * Read next file stat buffer
 *
 * Returns file reader tid on success, -1 on failure.
 *
 */
void read_next_mmapped_file_stats(struct mmapped_file * file) {
	assert(!feof(mmaps_file));
	/* XXX this could be considerably faster, simpler, and
	 * memory-safer ... */
	char line0[1024], *line = line0;
	if (fgets(line, 1024, mmaps_file) != NULL) {
		file->time = str2li(line,LI_COLUMN_SIZE);
		line += LI_COLUMN_SIZE;
		file->tid = str2li(line,LI_COLUMN_SIZE);
		line += LI_COLUMN_SIZE;
		file->copied = str2li(line,LI_COLUMN_SIZE);
		line += LI_COLUMN_SIZE;
		file->start = str2x(line,LI_COLUMN_SIZE);
		line += LI_COLUMN_SIZE;
		file->end= str2x(line,LI_COLUMN_SIZE);
		line += LI_COLUMN_SIZE;
		file->stat.st_blksize = str2li(line,LI_COLUMN_SIZE);
		line += LI_COLUMN_SIZE;
		file->stat.st_blocks = str2li(line,LI_COLUMN_SIZE);
		line += LI_COLUMN_SIZE;
		file->stat.st_ctim.tv_sec = str2li(line,LI_COLUMN_SIZE);
		line += LI_COLUMN_SIZE;
		file->stat.st_ctim.tv_nsec = str2li(line,LI_COLUMN_SIZE);
		line += LI_COLUMN_SIZE;
		file->stat.st_dev = str2li(line,LI_COLUMN_SIZE);
		line += LI_COLUMN_SIZE;
		file->stat.st_gid = str2li(line,LI_COLUMN_SIZE);
		line += LI_COLUMN_SIZE;
		file->stat.st_ino = str2li(line,LI_COLUMN_SIZE);
		line += LI_COLUMN_SIZE;
		file->stat.st_mode = str2li(line,LI_COLUMN_SIZE);
		line += LI_COLUMN_SIZE;
		file->stat.st_mtim.tv_sec = str2li(line,LI_COLUMN_SIZE);
		line += LI_COLUMN_SIZE;
		file->stat.st_mtim.tv_nsec = str2li(line,LI_COLUMN_SIZE);
		line += LI_COLUMN_SIZE;
		file->stat.st_rdev = str2li(line,LI_COLUMN_SIZE);
		line += LI_COLUMN_SIZE;
		file->stat.st_size = str2li(line,LI_COLUMN_SIZE);
		line += LI_COLUMN_SIZE;
		file->stat.st_uid = str2li(line,LI_COLUMN_SIZE);
		line += LI_COLUMN_SIZE;
		strcpy(file->filename,line);
		// get rid of the \n
		file->filename[strlen(file->filename) - 1] = '\0';
	}
}

void peek_next_mmapped_file_stats(struct mmapped_file * file)
{
	fpos_t pos;
	fgetpos(mmaps_file, &pos);
	read_next_mmapped_file_stats(file);
	fsetpos(mmaps_file, &pos);
}

void peek_next_trace(struct trace_frame *trace)
{
	fpos_t pos;
	fgetpos(trace_file, &pos);
	int saved_trace_file_lines_counter = trace_file_lines_counter;
	read_next_trace(trace);
	/* check if read is successful */
	assert(!feof(trace_file));
	trace_file_lines_counter = saved_trace_file_lines_counter;
	fsetpos(trace_file, &pos);
}

void read_next_trace(struct trace_frame *trace)
{
	char line[1024];

	char * tmp_ptr = fgets(line, 1024, trace_file);
	if (tmp_ptr != line) {
		use_new_trace_file();
		tmp_ptr = fgets(line, 1024, trace_file);
		assert(tmp_ptr == line);
	}
	++trace_file_lines_counter;

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

	// TODO: perf counters are only needed for signals
	/* read hardware performance counters */
	trace->hw_interrupts = str2ull(tmp_ptr, UUL_COLUMN_SIZE);
	tmp_ptr += UUL_COLUMN_SIZE;
	trace->page_faults = str2ull(tmp_ptr, UUL_COLUMN_SIZE);
	tmp_ptr += UUL_COLUMN_SIZE;
	trace->rbc = str2ull(tmp_ptr, UUL_COLUMN_SIZE);
	tmp_ptr += UUL_COLUMN_SIZE;
	trace->insts = str2ull(tmp_ptr, UUL_COLUMN_SIZE);
	tmp_ptr += UUL_COLUMN_SIZE;

	//read register file
	parse_register_file(&(trace->recorded_regs), tmp_ptr);
}

int get_trace_file_lines_counter()
{
    return trace_file_lines_counter;
}

void find_in_trace(struct context *ctx, unsigned long cur_time, long int val)
{
	fpos_t pos;

	fgetpos(trace_file, &pos);
	int saved_trace_file_lines_counter = trace_file_lines_counter;
	rewind(trace_file);
	/* skip the header */
	char* line = sys_malloc(1024);

	read_line(trace_file, line, 1024, "trace");
	struct trace_frame trace;
	do {
		read_next_trace(&trace);
		if ((val == trace.recorded_regs.eax) || (val == trace.recorded_regs.ebx) || (val == trace.recorded_regs.ecx) || (val == trace.recorded_regs.edx) || (val == trace.recorded_regs.esi)
				|| (val == trace.recorded_regs.edi) || (val == trace.recorded_regs.ebp) || (val == trace.recorded_regs.orig_eax)) {

			printf("found val: %lx at time: %u\n", val, trace.global_time);
		}

	} while (trace.global_time < cur_time);

	sys_free((void**) &line);
	fsetpos(trace_file, &pos);
	trace_file_lines_counter = saved_trace_file_lines_counter;
	assert(0);
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



