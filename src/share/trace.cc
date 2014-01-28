/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

//#define DEBUGTAG "Trace"

#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "config.h"
#include "dbg.h"
#include "hpc.h"
#include "ipc.h"
#include "sys.h"
#include "task.h"
#include "trace.h"
#include "util.h"

#include "../preload/syscall_buffer.h"

#define BUF_SIZE 1024;
#define LINE_SIZE 50;

using namespace std;

static char trace_path_[PATH_MAX];

static FILE *syscall_header;
static FILE *raw_data;
static int trace_file_fd = -1;
static FILE *mmaps_file;

static int raw_data_file_counter = 0;
static uint32_t trace_file_counter = 0;
/* Global time starts at "1" so that conditions like |global_time %
 * interval| don't have to consider the trivial case |global_time ==
 * 0|. */
static uint32_t global_time = 1;
static int read_first_trace_frame = 0;

// counts the number of raw bytes written, a new raw_data file is used when MAX_RAW_DATA_SIZE is reached
static long long overall_raw_bytes = 0;

static ssize_t sizeof_trace_frame_event_info(void)
{
	return offsetof(struct trace_frame, end_event_info) -
		offsetof(struct trace_frame, begin_event_info);
}

static ssize_t sizeof_trace_frame_exec_info(void)
{
	return offsetof(struct trace_frame, end_exec_info) -
		offsetof(struct trace_frame, begin_exec_info);
}

void flush_trace_files(void)
{
	fflush(syscall_header);
	fflush(raw_data);
	fflush(mmaps_file);
}

const char* get_trace_path()
{
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
	if (0 <= event) {
		return syscallname(event);
	}
	return "???event";
}

void dump_trace_frame(FILE* out, const struct trace_frame* f)
{
	const struct user_regs_struct* r = &f->recorded_regs;

	fprintf(out,
"{\n  global_time:%u, event:`%s' (state:%d), tid:%d, thread_time:%u",
		f->global_time, strevent(f->stop_reason), f->state,
		f->tid, f->thread_time);
	if (!f->has_exec_info) {
		fprintf(out, "\n}\n");
		return;
	}

	fprintf(out,
"\n  hw_ints:%lld, faults:%lld, rbc:%lld, insns:%lld"
"\n  eax:0x%lx ebx:0x%lx ecx:0x%lx edx:0x%lx esi:0x%lx edi:0x%lx ebp:0x%lx"
"\n  eip:0x%lx esp:0x%lx eflags:0x%lx orig_eax:%ld\n}\n",
		f->hw_interrupts, f->page_faults, f->rbc, f->insts,
		r->eax, r->ebx, r->ecx, r->edx, r->esi, r->edi, r->ebp,
		r->eip, r->esp, r->eflags, r->orig_eax);
}

/**
 * Return the encoded event number of |ev| that's suitable for saving
 * to trace.  |state| is set to the corresponding execution state and
 * may be null.
 */
static int encode_event(const struct event* ev, int* state)
{
	int dummy;

	state = state ? state : &dummy;
	switch (ev->type) {
	case EV_DESCHED:
		switch (ev->desched.state) {
		case IN_SYSCALL:
			return USR_ARM_DESCHED;
		case DISARMED_DESCHED_EVENT:
			return USR_DISARM_DESCHED;
		default:
			fatal("Unhandled desched state %d", ev->desched.state);
		}

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
			TRANSLATE(USR_SYSCALLBUF_FLUSH);
			TRANSLATE(USR_SYSCALLBUF_ABORT_COMMIT);
			TRANSLATE(USR_SYSCALLBUF_RESET);
			TRANSLATE(USR_UNSTABLE_EXIT);
			TRANSLATE(USR_TRACE_TERMINATION);
		default:
			fatal("Unknown pseudosig %d", ev->pseudosig.no);
#undef TRANSLATE
		}

	case EV_SIGNAL:
	case EV_SIGNAL_DELIVERY:
	case EV_SIGNAL_HANDLER: {
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

		*state = (ev->syscall.state == ENTERING_SYSCALL) ?
			 STATE_SYSCALL_ENTRY : STATE_SYSCALL_EXIT;
		return event;
	}

	default:
		fatal("Unknown event type %d", ev->type);
		return -(1 << 30); /* not reached */
	}
}

unsigned int get_global_time(void)
{
	return global_time;
}

void rec_setup_trace_dir()
{
	int nonce = 0;
	const char* output_dir;
	int ret;

	if (!(output_dir = getenv("_RR_TRACE_DIR"))) {
		output_dir = ".";
	}
	/* Find a unique trace directory name. */
	do {
		snprintf(trace_path_, sizeof(trace_path_) - 1,
			 "%s/trace_%d", output_dir, nonce++);
		ret = mkdir(trace_path_,
			    S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	} while (ret && EEXIST == errno);

	if (ret) {
		fatal("Unable to create trace directory `%s'", trace_path_);
	}
	log_info("Saving trace files to %s", trace_path_);
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

static void use_new_rawdata_file(void)
{
	char path[PATH_MAX];

	if (raw_data) {
		sys_fclose(raw_data);
	}
	overall_raw_bytes = 0;

	snprintf(path, sizeof(path) - 1,
		 "%s/raw_data_%u", trace_path_, raw_data_file_counter++);
	raw_data = sys_fopen(path, "a+");
}

static void use_new_trace_file(void)
{
	char path[PATH_MAX];

	close(trace_file_fd);

	snprintf(path, sizeof(path) - 1,
		 "%s/trace_%u", trace_path_, trace_file_counter++);
	trace_file_fd = open(path, O_APPEND | O_CLOEXEC | O_CREAT | O_RDWR,
			     0600);
	if (0 > trace_file_fd) {
		fatal("Failed to open trace file `%s'", path);
	}
}

static void ensure_current_trace_file(void)
{
	/* Global time starts at "1", so we won't switch to a new log
	 * on the first event. */
	if (global_time % MAX_TRACE_ENTRY_SIZE == 0) {
		use_new_trace_file();
	}
}

void open_trace_files(void)
{
	char path[PATH_MAX];

	use_new_trace_file();

	snprintf(path, sizeof(path) - 1, "%s/syscall_input", trace_path_);
	syscall_header = sys_fopen(path, "a+");

	use_new_rawdata_file();

	snprintf(path, sizeof(path) - 1, "%s/mmaps", trace_path_);
	mmaps_file = sys_fopen(path, "a+");
}

void rec_init_trace_files(void)
{
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
	fflush(syscall_header);
	fflush(raw_data);
}

void close_trace_files(void)
{
	close(trace_file_fd);
	if (syscall_header)
		sys_fclose(syscall_header);
	if (raw_data)
		sys_fclose(raw_data);
	if (mmaps_file)
		sys_fclose(mmaps_file);
}

/**
 * Flush the syscallbuf to the trace, if there are any pending entries.
 */
static void maybe_flush_syscallbuf(Task *t)
{
	if (!t || !t->syscallbuf_hdr
	    || 0 == t->syscallbuf_hdr->num_rec_bytes 
	    || t->delay_syscallbuf_flush) {
		/* No context, no syscallbuf, or no records.  Nothing
		 * to do. */
		return;
	}
	/* Write the entire buffer in one shot without parsing it,
	 * since replay will take care of that. */
	push_pseudosig(t, EUSR_SYSCALLBUF_FLUSH, NO_EXEC_INFO);
	record_parent_data(t,
			   /* Record the header for consistency checking. */
			   t->syscallbuf_hdr->num_rec_bytes + sizeof(*t->syscallbuf_hdr),
			   t->syscallbuf_child, t->syscallbuf_hdr);
	record_event(t);
	pop_pseudosig(t);

	/* Reset header. */
	assert(!t->syscallbuf_hdr->abort_commit);
	if (!t->delay_syscallbuf_reset) {
		t->syscallbuf_hdr->num_rec_bytes = 0;
	}
	t->flushed_syscallbuf = 1;
}

/**
 * Return nonzero if a tracee at |ev| has meaningful execution info
 * (registers etc.)  that rr should record.  "Meaningful" means that
 * the same state will be seen when reaching this event during replay.
 */
static int has_exec_info(const struct event* ev)
{
	switch (ev->type) {
	case EV_DESCHED: {
		int dontcare;
		/* By the time the tracee is in the buffered syscall,
		 * it's by definition already armed the desched event.
		 * So we're recording that event ex post facto, and
		 * there's no meaningful execution information. */
		return USR_ARM_DESCHED != encode_event(ev, &dontcare);
	}
	case EV_PSEUDOSIG:
		return ev->pseudosig.has_exec_info;
	default:
		return 1;
	}
}

/**
 * Translate |t|'s event |ev| into a trace frame that can be saved to
 * the log.
 */
static void encode_trace_frame(Task* t, const struct event* ev,
			       struct trace_frame* frame)
{
	int state;

	memset(frame, 0, sizeof(*frame));

	frame->global_time = global_time++;
	frame->thread_time = t->thread_time++;
	frame->tid = t->tid;
	frame->stop_reason = encode_event(ev, &state);
	frame->state = state;
	frame->has_exec_info = has_exec_info(ev);
	if (frame->has_exec_info) {
		frame->hw_interrupts = read_hw_int(t->hpc);
		frame->page_faults = read_page_faults(t->hpc);
		frame->rbc = read_rbc(t->hpc);
		frame->insts = read_insts(t->hpc);
		read_child_registers(t, &frame->recorded_regs);
	}
}

/**
 * Write |frame| to the log.  Succeed or don't return.
 */
static void write_trace_frame(const struct trace_frame* frame)
{
	void* begin_data = (void*)&frame->begin_event_info;
	ssize_t nbytes = sizeof_trace_frame_event_info();
	ssize_t nwritten;

	ensure_current_trace_file();

	/* TODO: only store exec info for non-async-sig events when
	 * debugging assertions are enabled. */
	if (frame->has_exec_info) {
		nbytes += sizeof_trace_frame_exec_info();
	}
	nwritten = write(trace_file_fd, begin_data, nbytes);
	if (nwritten != nbytes) {
		fatal("Tried to save %d bytes to the trace, but only wrote %d",
		      nbytes, nwritten);
	}
}

void record_event(Task *t)
{
	struct trace_frame frame;

	/* If there's buffered syscall data, we need to record a flush
	 * event before recording |frame|, so that they're replayed in
	 * the correct order. */
	if (USR_SYSCALLBUF_FLUSH != encode_event(t->ev, NULL)) {
		maybe_flush_syscallbuf(t);
	}

	/* NB: we must encode the frame *after* flushing the
	 * syscallbuf, because encoding the frame has side effects on
	 * the global and thread clocks. */
	encode_trace_frame(t, t->ev, &frame);

	if (should_dump_memory(t, frame.stop_reason, frame.state,
			       frame.global_time)) {
		dump_process_memory(t, "rec");
	}		
	if (should_checksum(t, frame.stop_reason, frame.state,
			    frame.global_time)) {
		checksum_process_memory(t);
	}

	write_trace_frame(&frame);

	if (frame.has_exec_info) {
		reset_hpc(t, rr_flags()->max_rbc);
	}
}

static void print_header(int syscallno, void* addr)
{
	fprintf(syscall_header, "%11u", global_time);
	fprintf(syscall_header, "%11d", syscallno);
	fprintf(syscall_header, "%11u", (uintptr_t)addr);
}

static void write_raw_data(Task *t, void *buf, size_t to_write)
{
	size_t bytes_written;
	(void)bytes_written;

	bytes_written = fwrite(buf, 1, to_write, raw_data);
	assert(bytes_written == to_write);
	overall_raw_bytes += to_write;

	if (overall_raw_bytes > MAX_RAW_DATA_SIZE) {
		use_new_rawdata_file();
	}
}

/**
 * Writes data into the raw_data file and generates a corresponding entry in
 * syscall_input.
 */

#define SMALL_READ_SIZE	4096

void record_child_data(Task *t, size_t size, byte* child_ptr)
{
	int state;
	int event = encode_event(t->ev, &state);
	void* buf;
	ssize_t read_bytes;

	/* We shouldn't be recording a scratch address */
	assert_exec(t, !child_ptr || child_ptr != t->scratch_ptr, "");

	maybe_flush_syscallbuf(t);

	if (!child_ptr) {
		read_bytes = 0;
		goto record_read;
	}
	if (size <= SMALL_READ_SIZE) {
		char read_buffer[SMALL_READ_SIZE];

		read_child_usr(t, read_buffer, child_ptr, size);
		write_raw_data(t, read_buffer, size);
		read_bytes = size;
		goto record_read;
	}

	buf = read_child_data_checked(t, size, child_ptr, &read_bytes);
	assert_exec(t, read_bytes == ssize_t(size),
		    "Failed to read %d bytes at %p", size, child_ptr);

	write_raw_data(t, buf, read_bytes);
	free(buf);

record_read:
	print_header(event, child_ptr);
	fprintf(syscall_header, "%11d\n", read_bytes);
}

void record_parent_data(Task *t, size_t len, void *addr, void *buf)
{
	int state;
	int event = encode_event(t->ev, &state);
	(void)state;

	/* We shouldn't be recording a scratch address */
	assert(addr != t->scratch_ptr);

	write_raw_data(t, buf, len);
	print_header(event, addr);
	assert(len >= 0);
	fprintf(syscall_header, "%11d\n", len);
}

void record_mmapped_file_stats(struct mmapped_file *file)
{
	// XXX rewrite me
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

void record_child_str(Task* t, byte* child_ptr)
{
	int state;
	int event = encode_event(t->ev, &state);
	(void)state;

	print_header(event, child_ptr);
	char* buf = read_child_str(t, child_ptr);
	size_t len = strlen(buf) + 1;
	fprintf(syscall_header, "%11d\n", len);
	size_t bytes_written = fwrite(buf, 1, len, raw_data);
	(void)bytes_written;
	overall_raw_bytes += len;

	assert(bytes_written == len);
	free(buf);

	// new raw data file
	if (overall_raw_bytes > MAX_RAW_DATA_SIZE)
		use_new_rawdata_file();

}

void rep_setup_trace_dir(const char* path)
{
	strncpy(trace_path_, path, sizeof(trace_path_) - 1);
}

void rep_init_trace_files(void)
{
	char line[1024];

	/* The first line of these files is a header, which we eat. */
	read_line(syscall_header, line, 1024, "syscall_input");
	read_line(mmaps_file, line, 1024, "stats");
}

void load_recorded_env(const char* trace_path,
		       int* argc, string* exe_image,
		       CharpVector* argv, CharpVector* envp)
{
	string arg_env_path = trace_path;
	arg_env_path += "/arg_env";

	FILE* arg_env = sys_fopen(arg_env_path.c_str(), "r");
	char buf[8192];

	/* the first line contains argc */
	read_line(arg_env, buf, sizeof(buf), "arg_env");
	*argc = str2li(buf, LI_COLUMN_SIZE);

	/* followed by argv */
	for (int i = 0; i < *argc; ++i) {
		read_line(arg_env, buf, sizeof(buf), "arg_env");
		int len = strlen(buf);
		assert(len < 8192);
		/* overwrite the newline */
		buf[len - 1] = '\0';
		argv->push_back(strdup(buf));
	}

	/* do not forget write NULL to the last element */
	argv->push_back(NULL);
	*exe_image = argv->at(0);

	/* now, read the number of environment entries */
	read_line(arg_env, buf, sizeof(buf), "arg_env");
	int envc = str2li(buf, LI_COLUMN_SIZE);

	/* followed by argv */
	for (int i = 0; i < envc; i++) {
		read_line(arg_env, buf, sizeof(buf), "arg_env");
		int len = strlen(buf);
		assert(len < 8192);
		/* overwrite the newline */
		buf[len - 1] = '\0';
		envp->push_back(strdup(buf));
	}

	/* do not forget write NULL to the last element */
	envp->push_back(NULL);

	/* clean up */
	sys_fclose(arg_env);
}

static size_t parse_raw_data_hdr(struct trace_frame* trace, byte** addr)
{
	/* XXX rewrite me */
	char line[1024];
	char* tmp_ptr;
	uint32_t time;
	int syscall, size;

	read_line(syscall_header, line, 1024, "syscall_input");
	tmp_ptr = line;

	time = str2li(tmp_ptr, LI_COLUMN_SIZE);
	tmp_ptr += LI_COLUMN_SIZE;
	syscall = str2li(tmp_ptr, LI_COLUMN_SIZE);
	tmp_ptr += LI_COLUMN_SIZE;
	*addr = (byte*)str2li(tmp_ptr, LI_COLUMN_SIZE);
	tmp_ptr += LI_COLUMN_SIZE;
	size = str2li(tmp_ptr, LI_COLUMN_SIZE);

	if (time != trace->global_time
	    || (trace->stop_reason != SYS_restart_syscall
		&& syscall != trace->stop_reason)) {
		fatal("trace and syscall_input out of sync: trace is at (time=%d, %s), but input is for (time=%d, %s)",
		      trace->global_time, strevent(trace->stop_reason),
		      time, strevent(syscall));
	}
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

void* read_raw_data(struct trace_frame* trace, size_t* size_ptr, byte** addr)
{
	size_t size = parse_raw_data_hdr(trace, addr);
	void* data = NULL;

	*size_ptr = size;
	if (!*addr) {
		return NULL;
	}

	data = malloc(size);
	read_rawdata(data, size);
	return data;
}

ssize_t read_raw_data_direct(struct trace_frame* trace,
			     void* buf, size_t buf_size, byte** rec_addr)
{
	size_t data_size = parse_raw_data_hdr(trace, rec_addr);

	if (!*rec_addr) {
		return 0;
	}

	assert(data_size <= buf_size);
	read_rawdata(buf, data_size);
	return data_size;
}

pid_t get_recorded_main_thread(void)
{
	struct trace_frame frame;

	assert(1 == get_global_time());

	peek_next_trace(&frame);
	return frame.tid;
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
	line = fgets(line, 1024, mmaps_file);
	assert(line);

	file->time = str2li(line,LI_COLUMN_SIZE);
	line += LI_COLUMN_SIZE;
	file->tid = str2li(line,LI_COLUMN_SIZE);
	line += LI_COLUMN_SIZE;
	file->copied = str2li(line,LI_COLUMN_SIZE);
	line += LI_COLUMN_SIZE;
	file->start = str2x(line,LI_COLUMN_SIZE);
	line += LI_COLUMN_SIZE;
	file->end = str2x(line,LI_COLUMN_SIZE);
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

void peek_next_mmapped_file_stats(struct mmapped_file* file)
{
	fpos_t pos;
	fgetpos(mmaps_file, &pos);
	read_next_mmapped_file_stats(file);
	fsetpos(mmaps_file, &pos);
}

void peek_next_trace(struct trace_frame* trace)
{
	/* FIXME if peeking causes the trace file to roll over, then
	 * things will go haywire. */
	off_t pos = lseek(trace_file_fd, 0, SEEK_CUR);
	uint32_t saved_global_time = global_time;
	int saved_read_first_trace_frame = read_first_trace_frame;

	read_next_trace(trace);

	read_first_trace_frame = saved_read_first_trace_frame;
	global_time = saved_global_time;
	lseek(trace_file_fd, pos, SEEK_SET);
}

int try_read_next_trace(struct trace_frame *frame)
{
	ssize_t nread;

	memset(frame, 0, sizeof(*frame));

	/* This is the global time for the *next* frame, the one we're
	 * about to read.  For the first frame, the global time is
	 * already correct. */
	global_time += read_first_trace_frame ? 1 : 0;
	read_first_trace_frame = 1;

	ensure_current_trace_file();

	/* Read the common event info first, to see if we also have
	 * exec info to read. */
	nread = read(trace_file_fd, &frame->begin_event_info,
		     sizeof_trace_frame_event_info());
	if (sizeof_trace_frame_event_info() != nread) {
		return 0;
	}

	if (frame->has_exec_info) {
		nread = read(trace_file_fd, &frame->begin_exec_info,
			     sizeof_trace_frame_exec_info());
		if (sizeof_trace_frame_exec_info() != nread) {
			return 0;
		}
	}

	assert(global_time == frame->global_time);
	return 1;
}

void read_next_trace(struct trace_frame* frame)
{
	int read_ok = try_read_next_trace(frame);
	assert(read_ok);
}
