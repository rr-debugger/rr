/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

//#define DEBUGTAG "Util"

//#define FIRST_INTERESTING_EVENT 10700
//#define LAST_INTERESTING_EVENT 10900

#include "util.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libdis.h>
#include <limits.h>
#include <linux/futex.h>
#include <linux/magic.h>
#include <linux/net.h>
#include <linux/perf_event.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
// This header has to be included after sys/ptrace.h.
#include <asm/ptrace-abi.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <limits>

#include "dbg.h"
#include "hpc.h"
#include "ipc.h"
#include "sys.h"
#include "task.h"
#include "trace.h"
#include "types.h"

#include "../preload/syscall_buffer.h"
#include "../recorder/rec_sched.h"
#include "../replayer/replayer.h"

using namespace std;

/* The tracee doesn't open the desched event fd during replay, so it
 * can't be shared to this process.  We pretend that the tracee shared
 * this magic fd number with us and then give it a free pass for fd
 * checks that include this fd. */
#define REPLAY_DESCHED_EVENT_FD -123
#define NUM_MAX_MAPS 1024

struct flags flags = { 0 };

const byte syscall_insn[] = { 0xcd, 0x80 };

const struct flags* rr_flags(void)
{
	return &flags;
}

struct flags* rr_flags_for_init(void)
{
	static int initialized;
	if (!initialized) {
		initialized = 1;
		return &flags;
	}
	fatal("Multiple initialization of flags.");
	return NULL;		/* not reached */
}

/**
 * Return nonzero if |addr| falls within |info|'s segment.
 */
static int addr_in_segment(void* addr, const struct mapped_segment_info* info)
{
	return info->start_addr <= addr && addr < info->end_addr;
}

static int find_segment_iterator(void* it_data, Task* t,
				 const struct map_iterator_data* data)
{
	struct mapped_segment_info* info =
		(struct mapped_segment_info*)it_data;
	void* search_addr = info->start_addr;
	if (addr_in_segment(search_addr, &data->info)) {
		memcpy(info, &data->info, sizeof(*info));
		return STOP_ITERATING;
	}
	return CONTINUE_ITERATING;
}

/**
 * Search for the segment containing |search_addr|, and if found copy
 * out the segment info to |info| and return nonzero.  Return zero if
 * not found.
 */
static int find_segment_containing(Task* t, byte* search_addr,
			    struct mapped_segment_info* info)
{
	memset(info, 0, sizeof(*info));
	info->start_addr = search_addr;
	iterate_memory_map(t, find_segment_iterator, info,
			   kNeverReadSegment, NULL);
	return addr_in_segment(search_addr, info);
}

static byte* get_mmaped_region_end(Task* t, byte* start)
{
	struct mapped_segment_info info;
	int found_info = find_segment_containing(t, start, &info);
	assert_exec(t, found_info, "Didn't find segment containing %p", start);
	return info.end_addr;
}

// FIXME this function assumes that there's only one address space.
// Should instead only look at the address space of the task in
// question.
static bool is_start_of_scratch_region(void* start_addr)
{
	for (Task::Map::const_iterator it = Task::begin(); it != Task::end();
	     ++it) {
		Task* t = it->second;
		if (start_addr == t->scratch_ptr) {
			return true;
		}
	}
	return false;
}

double now_sec(void)
{
	struct timespec tp;
	clock_gettime(CLOCK_MONOTONIC, &tp);
	return (double)tp.tv_sec + (double)tp.tv_nsec / 1e9;
}

int nanosleep_nointr(const struct timespec* ts)
{
	struct timespec req = *ts;
	while (1) {
		struct timespec rem;
		int err = nanosleep(&req, &rem);
		if (0 == err || EINTR != errno) {
			return err;
		}
		req = rem;
	}
}

int probably_not_interactive(void)
{
	/* Eminently tunable heuristic, but this is guaranteed to be
	 * true during rr unit tests, where we care most about this
	 * check (to a first degree).  A failing test shouldn't
	 * hang. */
	return !isatty(STDERR_FILENO);
}

void maybe_mark_stdio_write(Task* t, int fd)
{
	char buf[256];
	ssize_t len;

	if (!rr_flags()->mark_stdio || !(STDOUT_FILENO == fd
					 || STDERR_FILENO == fd)) {
		return;
	}
	snprintf(buf, sizeof(buf) - 1, "[rr.%d]", get_global_time());
	len = strlen(buf);
	if (write(fd, buf, len) != len) {
		fatal("Couldn't write to %d", fd);
	}
}

const char* ptrace_event_name(int event)
{
	switch (event) {
#define CASE(_id) case PTRACE_EVENT_## _id: return #_id
	CASE(FORK);
	CASE(VFORK);
	CASE(CLONE);
	CASE(EXEC);
	CASE(VFORK_DONE);
	CASE(EXIT);
	/* XXX Ubuntu 12.04 defines a "PTRACE_EVENT_STOP", but that
	 * has the same value as the newer EVENT_SECCOMP, so we'll
	 * ignore STOP. */
#ifdef PTRACE_EVENT_SECCOMP_OBSOLETE
	CASE(SECCOMP_OBSOLETE);
#else
	CASE(SECCOMP);
#endif
	default:
		return "???EVENT";
#undef CASE
	}
}

const char* ptrace_req_name(int request)
{
#define CASE(_id) case PTRACE_## _id: return #_id
	switch (int(request)) {
	CASE(TRACEME);
	CASE(PEEKTEXT);
	CASE(PEEKDATA);
	CASE(PEEKUSER);
	CASE(POKETEXT);
	CASE(POKEDATA);
	CASE(POKEUSER);
	CASE(CONT);
	CASE(KILL);
	CASE(SINGLESTEP);
	CASE(GETREGS);
	CASE(SETREGS);
	CASE(GETFPREGS);
	CASE(SETFPREGS);
	CASE(ATTACH);
	CASE(DETACH);
	CASE(GETFPXREGS);
	CASE(SETFPXREGS);
	CASE(SYSCALL);
	CASE(SETOPTIONS);
	CASE(GETEVENTMSG);
	CASE(GETSIGINFO);
	CASE(SETSIGINFO);
	CASE(GETREGSET);
	CASE(SETREGSET);
	CASE(SEIZE);
	CASE(INTERRUPT);
	CASE(LISTEN);
	// These aren't part of the official ptrace-request enum.
	CASE(SYSEMU);
	CASE(SYSEMU_SINGLESTEP);
#undef CASE
	default:
		return "???REQ";
	}
}

const char* signalname(int sig)
{
	/* strsignal() would be nice to use here, but it provides TMI. */
	if (SIGRTMIN <= sig && sig <= SIGRTMAX) {
		static __thread char buf[] = "SIGRT00000000";
		snprintf(buf, sizeof(buf) - 1, "SIGRT%d", sig - SIGRTMIN);
		return buf;
	}

	switch (sig) {
#define CASE(_id) case _id: return #_id
	CASE(SIGHUP); CASE(SIGINT); CASE(SIGQUIT); CASE(SIGILL);
	CASE(SIGTRAP); CASE(SIGABRT); /*CASE(SIGIOT);*/ CASE(SIGBUS);
	CASE(SIGFPE); CASE(SIGKILL); CASE(SIGUSR1); CASE(SIGSEGV);
	CASE(SIGUSR2); CASE(SIGPIPE); CASE(SIGALRM); CASE(SIGTERM);
	CASE(SIGSTKFLT); /*CASE(SIGCLD);*/ CASE(SIGCHLD); CASE(SIGCONT);
	CASE(SIGSTOP); CASE(SIGTSTP); CASE(SIGTTIN); CASE(SIGTTOU);
	CASE(SIGURG); CASE(SIGXCPU); CASE(SIGXFSZ); CASE(SIGVTALRM);
	CASE(SIGPROF); CASE(SIGWINCH); /*CASE(SIGPOLL);*/ CASE(SIGIO);
	CASE(SIGPWR); CASE(SIGSYS);
#undef CASE

	default:
		return "???signal";
	}
}

const char* syscallname(int syscall)
{
	switch (syscall) {
#define SYSCALL_DEF(_, _name, __) case __NR_## _name: return #_name;
#include "../replayer/syscall_defs.h"
#undef SYSCALL_DEF

	case SYS_restart_syscall:
		return "restart_syscall";
	default:
		return "???syscall";
	}
}

int clone_flags_to_task_flags(int flags_arg)
{
	int flags = CLONE_SHARE_NOTHING;
	// See task.h for description of the flags.
	flags |= (CLONE_CHILD_CLEARTID & flags_arg) ? CLONE_CLEARTID : 0;
	flags |= (CLONE_SIGHAND & flags_arg) ? CLONE_SHARE_SIGHANDLERS : 0;
	flags |= (CLONE_THREAD & flags_arg) ? CLONE_SHARE_TASK_GROUP : 0;
	flags |= (CLONE_VM & flags_arg) ? CLONE_SHARE_VM : 0;
	return flags;
}

void print_register_file_tid(Task* t)
{
	struct user_regs_struct regs;
	t->get_regs(&regs);
	print_register_file(&regs);
}

void print_register_file(struct user_regs_struct* regs)
{
	fprintf(stderr, "Printing register file:\n");
	fprintf(stderr, "eax: %lx\n", regs->eax);
	fprintf(stderr, "ebx: %lx\n", regs->ebx);
	fprintf(stderr, "ecx: %lx\n", regs->ecx);
	fprintf(stderr, "edx: %lx\n", regs->edx);
	fprintf(stderr, "esi: %lx\n", regs->esi);
	fprintf(stderr, "edi: %lx\n", regs->edi);
	fprintf(stderr, "ebp: %lx\n", regs->ebp);
	fprintf(stderr, "esp: %lx\n", regs->esp);
	fprintf(stderr, "eip: %lx\n", regs->eip);
	fprintf(stderr, "eflags %lx\n",regs->eflags);
	fprintf(stderr, "orig_eax %lx\n", regs->orig_eax);
	fprintf(stderr, "xcs: %lx\n", regs->xcs);
	fprintf(stderr, "xds: %lx\n", regs->xds);
	fprintf(stderr, "xes: %lx\n", regs->xes);
	fprintf(stderr, "xfs: %lx\n", regs->xfs);
	fprintf(stderr, "xgs: %lx\n", regs->xgs);
	fprintf(stderr, "xss: %lx\n", regs->xss);
	fprintf(stderr, "\n");

}

/**
 * Remove leading blank characters from |str| in-place.  |str| must be
 * a valid string.
 */
static void trim_leading_blanks(char* str)
{
	char* trimmed = str;
	while (isblank(*trimmed)) ++trimmed;
	memmove(str, trimmed, strlen(trimmed) + 1/*\0 byte*/);
}

static int caller_wants_segment_read(Task* t,
				     const struct mapped_segment_info* info,
				     read_segment_filter_t filt,
				     void* filt_data)
{
	if (kNeverReadSegment == filt) {
		return 0;
	}
	if (kAlwaysReadSegment == filt) {
		return 1;
	}
	return filt(filt_data, t, info);
}

void iterate_memory_map(Task* t,
			memory_map_iterator_t it, void* it_data,
			read_segment_filter_t filt, void* filt_data)
{
	FILE* maps_file;
	char line[PATH_MAX];
	{
		char maps_path[PATH_MAX];
		snprintf(maps_path, sizeof(maps_path) - 1, "/proc/%d/maps",
			t->tid);
		assert_exec(t, (maps_file = fopen(maps_path, "r")),
			    "Failed to open %s", maps_path);
	}
	while (fgets(line, sizeof(line), maps_file)) {
		uint64_t start, end;
		struct map_iterator_data data;
		char flags[32];
		int nparsed;
		int next_action;

		memset(&data, 0, sizeof(data));
		data.raw_map_line = line;

		nparsed = sscanf(line, "%llx-%llx %31s %Lx %x:%x %Lu %s",
				 &start, &end,
				 flags, &data.info.file_offset,
				 &data.info.dev_major, &data.info.dev_minor,
				 &data.info.inode, data.info.name);
		assert_exec(t,
			    (8/*number of info fields*/ == nparsed
			     || 7/*num fields if name is blank*/ == nparsed),
			    "Only parsed %d fields of segment info from\n"
			    "%s",
			    nparsed, data.raw_map_line);

		trim_leading_blanks(data.info.name);
		if (start > numeric_limits<uint32_t>::max()
		    || end > numeric_limits<uint32_t>::max()
		    || !strcmp(data.info.name, "[vsyscall]")) {
			// We manually read the exe link here because
			// this helper is used to set
			// |t->vm()->exe_image()|, so we can't rely on
			// that being correct yet.
			char proc_exe[PATH_MAX];
			char exe[PATH_MAX];
			snprintf(proc_exe, sizeof(proc_exe),
				 "/proc/%d/exe", t->tid);
			readlink(proc_exe, exe, sizeof(exe));
			fatal("Sorry, tracee %d has x86-64 image %s and that's not supported.",
			      t->tid, exe);
		}
		data.info.start_addr = (byte*)start;
		data.info.end_addr = (byte*)end;

		data.info.prot |= strchr(flags, 'r') ? PROT_READ : 0;
		data.info.prot |= strchr(flags, 'w') ? PROT_WRITE : 0;
		data.info.prot |= strchr(flags, 'x') ? PROT_EXEC : 0;
		data.info.flags |= strchr(flags, 'p') ? MAP_PRIVATE : 0;
		data.info.flags |= strchr(flags, 's') ? MAP_SHARED : 0;
		data.size_bytes = ((intptr_t)data.info.end_addr -
				   (intptr_t)data.info.start_addr);
		if (caller_wants_segment_read(t, &data.info,
					      filt, filt_data)) {
			data.mem =
				(byte*)
				read_child_data_checked(t, data.size_bytes,
							data.info.start_addr,
							&data.mem_len);
			/* TODO: expose read errors, somehow. */
			data.mem_len = MAX(0, data.mem_len);
		}

		next_action = it(it_data, t, &data);
		free(data.mem);

		if (STOP_ITERATING == next_action) {
			break;
		}
	}
	fclose(maps_file);
}

static int print_process_mmap_iterator(void* unused, Task* t,
				       const struct map_iterator_data* data)
{
	fputs(data->raw_map_line, stderr);
	return CONTINUE_ITERATING;
}

void print_process_mmap(Task* t)
{
	return iterate_memory_map(t, print_process_mmap_iterator, NULL,
				  kNeverReadSegment, NULL);
}

char* get_inst(Task* t, int eip_offset, int* opcode_size)
{
	char* buf = NULL;
	unsigned long eip = t->get_eip();
	ssize_t nr_read_bytes;
	byte* inst =
		(byte*)read_child_data_checked(t, 128,
					       (byte*)(eip + eip_offset),
					       &nr_read_bytes);

	if (nr_read_bytes <= 0) {
		free(inst);
		return NULL;
	}

	x86_init(opt_none, 0, 0);

	x86_insn_t x86_inst;
	unsigned int size = x86_disasm(inst, 128, 0, 0, &x86_inst);
	*opcode_size = size;

	buf = (char*)malloc(128);
	if (size) {
		x86_format_insn(&x86_inst, buf, 128, att_syntax);
	} else {
		/* libdiasm does not support the entire instruction set -- pretty sad */
		strcpy(buf, "unknown");
	}
	free(inst);
	x86_oplist_free(&x86_inst);
	x86_cleanup();

	return buf;
}

void mprotect_child_region(Task* t, byte* addr, int prot)
{
	struct current_state_buffer state;
	size_t length;
	long ret;

	/* Page-align the address. */
	addr = (byte*)((uintptr_t)addr & PAGE_MASK);
	length = get_mmaped_region_end(t, addr) - addr;

	prepare_remote_syscalls(t, &state);
	ret = remote_syscall3(t, &state, SYS_mprotect, addr, length, prot);
	assert(ret == 0);
	finish_remote_syscalls(t, &state);
}

bool is_page_aligned(const byte* addr)
{
	return is_page_aligned(reinterpret_cast<size_t>(addr));
}

bool is_page_aligned(size_t sz)
{
	return 0 == (sz % page_size());
}

size_t page_size()
{
	return sysconf(_SC_PAGE_SIZE);
}

size_t ceil_page_size(size_t sz)
{
	size_t page_mask = ~(page_size() - 1);
	return (sz + page_size() - 1) & page_mask;
}

void print_inst(Task* t)
{
	int size;
	char* str = get_inst(t, 0, &size);
	printf("inst: %s\n", str);
	free(str);
}

void print_process_state(pid_t tid)
{
	char path[64];
	FILE* file;
	printf("child tid: %d\n", tid);
	fflush(stdout);
	bzero(path, 64);
	sprintf(path, "/proc/%d/status", tid);
	if ((file = fopen(path, "r")) == NULL) {
		perror("error reading child memory status\n");
	}

	int c = getc(file);
	while (c != EOF) {
		putchar(c);
		c = getc(file);
	}
	sys_fclose(file);
}


void print_cwd(pid_t tid, char *str)
{
	char path[64];
	fflush(stdout);
	bzero(path, 64);
	sprintf(path, "/proc/%d/cwd", tid);
	assert(readlink(path, str, 1024) != -1);
}


static void maybe_print_reg_mismatch(int mismatch_behavior, const char* regname,
				     const char* label1, long val1,
				     const char* label2, long val2)
{
	if (mismatch_behavior >= BAIL_ON_MISMATCH) {
		log_err("%s 0x%lx != 0x%lx (%s vs. %s)",
			regname, val1, val2, label1, label2);
	} else if (mismatch_behavior >= LOG_MISMATCHES) {
		log_info("%s 0x%lx != 0x%lx (%s vs. %s)",
			 regname, val1, val2, label1, label2);
	}
}

int compare_register_files(Task* t,
			   const char* name1,
			   const struct user_regs_struct* reg1,
			   const char* name2,
			   const struct user_regs_struct* reg2,
			   int mismatch_behavior)
{
	int bail_error = (mismatch_behavior >= BAIL_ON_MISMATCH);
	/* TODO: do any callers use this? */
	int errbit = 0;
	int err = 0;

#define REGCMP(_reg, _bit)						   \
	do {								   \
		if (reg1-> _reg != reg2-> _reg) {			   \
			maybe_print_reg_mismatch(mismatch_behavior, #_reg, \
						 name1, reg1-> _reg,	   \
						 name2, reg2-> _reg);	   \
			err |= (1 << (_bit));				   \
		}							   \
	} while (0)

	REGCMP(eax, ++errbit);
	REGCMP(ebx, ++errbit);
	REGCMP(ecx, ++errbit);
	REGCMP(edx, ++errbit);
	REGCMP(esi, ++errbit);
	REGCMP(edi, ++errbit);
	REGCMP(ebp, ++errbit);
	REGCMP(eip, ++errbit);
	REGCMP(xfs, ++errbit);
	REGCMP(xgs, ++errbit);
	/* The following are eflags that have been observed to be
	 * nondeterministic in practice.  We need to mask them off in
	 * this comparison to prevent replay from diverging. */
	enum {
		/* The linux kernel has been observed to report this
		 * as zero in some states during system calls. It
		 * always seems to be 1 during user-space execution so
		 * we should be able to ignore it. */
		RESERVED_FLAG_1 = 1 << 1,
		/* According to www.logix.cz/michal/doc/i386/chp04-01.htm
		 *
		 *   The RF flag temporarily disables debug exceptions
		 *   so that an instruction can be restarted after a
		 *   debug exception without immediately causing
		 *   another debug exception. Refer to Chapter 12 for
		 *   details.
		 *
		 * Chapter 12 isn't particularly clear on the point,
		 * but the flag appears to be set by |int3|
		 * exceptions.
		 *
		 * This divergence has been observed when continuing a
		 * tracee to an execution target by setting an |int3|
		 * breakpoint, which isn't used during recording.  No
		 * single-stepping was used during the recording
		 * either.
		 */
		RESUME_FLAG = 1 << 16,
		/* It's no longer known why this bit is ignored. */
		CPUID_ENABLED_FLAG = 1 << 21,
	};
	/* check the deterministic eflags */
	const long det_mask =
		~(RESERVED_FLAG_1 | RESUME_FLAG | CPUID_ENABLED_FLAG);
	long eflags1 = (reg1->eflags & det_mask);
	long eflags2 = (reg2->eflags & det_mask);
	if (eflags1 != eflags2) {
		maybe_print_reg_mismatch(mismatch_behavior, "deterministic eflags",
					 name1, eflags1, name2, eflags2);
		err |= (1 << ++errbit);
	}

	assert_exec(t, !bail_error || !err,
		    "Fatal register mismatch (rbc/rec:%lld/%lld)",
		    read_rbc(t->hpc), t->trace.rbc);

	if (!err && mismatch_behavior == LOG_MISMATCHES) {
		log_info("(register files are the same for %s and %s)",
			 name1, name2);
	}

	return err;
}

void assert_child_regs_are(Task* t,
			   const struct user_regs_struct* regs,
			   int event, int state)
{
	t->get_regs(&t->regs);
	compare_register_files(t, "replaying", &t->regs, "recorded", regs,
			       BAIL_ON_MISMATCH);
	/* TODO: add perf counter validations (hw int, page faults, insts) */
}

uint64_t str2ull(const char* start, size_t max_size)
{
	int idx = 0;
	while (start[idx] == ' ') {
		idx += 1;
	}

	uint64_t val = 0;
	while (isdigit(start[idx]) && idx <= ssize_t(max_size)) {
		char tmp_char[2];
		tmp_char[0] = start[idx];
		tmp_char[1] = '\0';
		int tmp = atoi(tmp_char);
		val *= 10;
		val += tmp;
		idx++;
	}
	return val;
}

long int str2li(const char* start, size_t max_size)
{
	int idx = 0;
	int sign = 1;

	while (start[idx] == ' ') {
		idx += 1;
	}

	if (start[idx] == '-') {
		idx += 1;
		sign = -1;
	}

	long int val = 0;
	while (isdigit(start[idx]) && idx <= ssize_t(max_size)) {
		char tmp_char[2];
		tmp_char[0] = start[idx];
		tmp_char[1] = '\0';
		int tmp = atoi(tmp_char);
		val *= 10;
		val += tmp;
		idx++;
	}

	val *= sign;
	return val;
}

byte* str2x(const char* start, size_t max_size)
{
	int idx = 0;

	while (start[idx] == ' ') {
		idx++;
	}

	long int val = 0;
	while (idx <= ssize_t(max_size)) {
		int tmp = 0;
		if (isdigit(start[idx])) {
			tmp = start[idx] - '0';
		} else if (isalpha(start[idx])) {
			tmp = 10 + start[idx] - 'a';
		} else {
			break;
		}
		val *= 16;
		val += tmp;
		idx++;
	}

	return (byte*)val;
}

void read_line(FILE* file, char* buf, int size, const char* name)
{
	if (feof(file) || fgets(buf, size, file) == NULL) {
		printf("error reading line in file: %s  -- bailing out\n", name);
		printf("buf: %p  size: %d\n",buf,size);
		perror("");
		exit(-1);
	}
}

/**
 * Dump |buf_len| words in |buf| to |out|, starting with a line
 * containing |label|.  See |dump_binary_data()| for a description of
 * the remaining parameters.
 */
static void dump_binary_chunk(FILE* out, const char* label,
			      const uint32_t* buf, size_t buf_len,
			      const byte* start_addr)
{
	int i;

	fprintf(out,"%s\n", label);
	for (i = 0 ; i < ssize_t(buf_len); i += 1) {
		uint32_t word = buf[i];
		fprintf(out, "0x%08x | [%p]\n", word,
			start_addr + i * sizeof(*buf));
	}
}

void dump_binary_data(const char* filename, const char* label,
		      const uint32_t* buf, size_t buf_len,
		      const byte* start_addr)
{
	FILE* out = fopen(filename, "w");
	if (!out) {
		return;
	}
	dump_binary_chunk(out, label, buf, buf_len, start_addr);
	fclose(out);
}

void format_dump_filename(Task* t, const char* tag,
			  char* filename, size_t filename_size)
{
	snprintf(filename, filename_size - 1, "%s/%d_%d_%s",
		 get_trace_path(), t->rec_tid, get_global_time(), tag);
}

int should_dump_memory(Task* t, int event, int state, int global_time)
{
	const struct flags* flags = rr_flags();

#if defined(FIRST_INTERESTING_EVENT)
	int is_syscall_exit = event >= 0 && state == STATE_SYSCALL_EXIT;
	if (is_syscall_exit
	    && RECORD == flags->option
	    && FIRST_INTERESTING_EVENT <= global_time
	    && global_time <= LAST_INTERESTING_EVENT) {
		return 1;
	}
	if (global_time > LAST_INTERESTING_EVENT) {
		return 0;
	}
#endif
	return (flags->dump_on == event || flags->dump_on == DUMP_ON_ALL
		|| flags->dump_at == global_time);
}

static int dump_process_memory_iterator(void* it_data, Task* t,
					const struct map_iterator_data* data)
{
	FILE* dump_file = (FILE*)it_data;
	const unsigned* buf = (const unsigned*)data->mem;
	byte* start_addr = data->info.start_addr;

	if (!buf) {
		/* This segment was filtered by debugging code. */
		return CONTINUE_ITERATING;
	}
	if (is_start_of_scratch_region(start_addr)) {
		/* Scratch regions will diverge between
		 * recording/replay, so including them in memory dumps
		 * makes comparing record/replay dumps very noisy. */
		return CONTINUE_ITERATING;
	}

	dump_binary_chunk(dump_file, data->raw_map_line,
			  buf, data->mem_len / sizeof(*buf), start_addr);

	return CONTINUE_ITERATING;
}

static int dump_process_memory_segment_filter(
	void* filt_data, Task* t,
	const struct mapped_segment_info* info)
{
	/* For debugging purposes, add segment filtering here, for
	 * example
	if (!strstr(info->name, "[stack]")) {
		return 0;
	}
	*/
	return 1;
}

void dump_process_memory(Task* t, const char* tag)
{
	char filename[PATH_MAX];
	FILE* dump_file;

	format_dump_filename(t, tag, filename, sizeof(filename));
	dump_file = fopen(filename,"w");

	/* flush all files in case we partially record
	 * TODO: what does that mean? */
	flush_trace_files();

	iterate_memory_map(t, dump_process_memory_iterator, dump_file,
			   dump_process_memory_segment_filter, NULL);
	fclose(dump_file);
}

static void notify_checksum_error(Task* t,
				  unsigned checksum, unsigned rec_checksum,
				  const struct map_iterator_data* data)
{
	int event = t->trace.stop_reason;
	char cur_dump[PATH_MAX];
	char rec_dump[PATH_MAX];

	dump_process_memory(t, "checksum_error");

	/* TODO: if the right recorder memory dump is present,
	 * automatically compare them, taking the oddball
	 * not-mapped-during-replay region(s) into account.  And if
	 * not present, tell the user how to make one in a future
	 * run. */
	format_dump_filename(t, "checksum_error", cur_dump, sizeof(cur_dump));
	format_dump_filename(t, "rec", rec_dump, sizeof(rec_dump));

	assert_exec(t, checksum == rec_checksum,
"Divergence in contents of memory segment after '%s':\n"
"\n"
"%s"
"    (recorded checksum:0x%x; replaying checksum:0x%x)\n"
"\n"
"Dumped current memory contents to %s. If you've created a memory dump for\n"
"the '%s' event (line %d) during recording by using, for example with\n"
"the args\n"
"\n"
"$ rr --dump-at=%d record ...\n"
"\n"
"then you can use the following to determine which memory cells differ:\n"
"\n"
"$ lcmp %s %s > mem-diverge.diff\n"
		    , strevent(event),
		    data->raw_map_line,
		    rec_checksum, checksum,
		    cur_dump, strevent(event),  get_global_time(),
		    get_global_time(),
		    rec_dump, cur_dump);
}

/**
 * This helper does the heavy lifting of storing or validating
 * checksums.  The iterator data determines which behavior the helper
 * function takes on, and to/from which file it writes/read.
 */
enum ChecksumMode { STORE_CHECKSUMS, VALIDATE_CHECKSUMS };
struct checksum_iterator_data {
		ChecksumMode mode;
	FILE* checksums_file;
};
static int checksum_iterator(void* it_data, Task* t,
			     const struct map_iterator_data* data)
{
	struct checksum_iterator_data* c =
		(struct checksum_iterator_data*)it_data;
	unsigned* buf = (unsigned*)data->mem;
	ssize_t valid_mem_len = data->mem_len;
	unsigned checksum = 0;
	int i;

	if (data->info.name ==
	    strstr(data->info.name, SYSCALLBUF_SHMEM_PATH_PREFIX)) {
		/* The syscallbuf consists of a region that's written
		 * deterministically wrt the trace events, and a
		 * region that's written nondeterministically in the
		 * same way as trace scratch buffers.  The
		 * deterministic region comprises committed syscallbuf
		 * records, and possibly the one pending record
		 * metadata.  The nondeterministic region starts at
		 * the "extra data" for the possibly one pending
		 * record.
		 *
		 * So here, we set things up so that we only checksum
		 * the deterministic region. */
		byte* child_hdr = data->info.start_addr;
		struct syscallbuf_hdr* hdr =
			(struct syscallbuf_hdr*)read_child_data(t,
								sizeof(*hdr),
								child_hdr);
		valid_mem_len = sizeof(*hdr) + hdr->num_rec_bytes +
				sizeof(struct syscallbuf_record);
		free(hdr);
	}

	/* If this segment was filtered, then data->mem_len will be 0
	 * to indicate nothing was read.  And data->mem will be NULL
	 * to double-check that.  In that case, the checksum will just
	 * be 0. */
	for (i = 0; i < ssize_t(valid_mem_len / sizeof(*buf)); ++i) {
		checksum += buf[i];
	}

	if (STORE_CHECKSUMS == c->mode) {
		fprintf(c->checksums_file,"(%x) %s",
			checksum, data->raw_map_line);
	} else {
		char line[1024];
		unsigned rec_checksum;
		void* rec_start_addr;
		void* rec_end_addr;
		int nparsed;

		fgets(line, sizeof(line), c->checksums_file);
		nparsed = sscanf(line, "(%x) %p-%p", &rec_checksum,
				 &rec_start_addr, &rec_end_addr);
		assert_exec(t, 3 == nparsed, "Only parsed %d items", nparsed);

		assert_exec(t, (rec_start_addr == data->info.start_addr
				&& rec_end_addr == data->info.end_addr),
			    "Segment %p-%p changed to %p-%p??",
			    rec_start_addr, rec_end_addr,
			    data->info.start_addr, data->info.end_addr);

		if (is_start_of_scratch_region(rec_start_addr)) {
			/* Replay doesn't touch scratch regions, so
			 * their contents are allowed to diverge.
			 * Tracees can't observe those segments unless
			 * they do something sneaky (or disastrously
			 * buggy). */
			debug("Not validating scratch starting at %p",
			      rec_start_addr);
			return CONTINUE_ITERATING;
		}
	 	if (checksum != rec_checksum) {
			notify_checksum_error(t, checksum, rec_checksum, data);
		}
	}
	return CONTINUE_ITERATING;
}

static int checksum_segment_filter(void* filt_data, Task* t,
				   const struct mapped_segment_info* info)
{
	struct stat st;
	int may_diverge;

	if (stat(info->name, &st)) {
		/* If there's no persistent resource backing this
		 * mapping, we should expect it to change. */
		debug("CHECKSUMMING unlinked '%s'", info->name);
		return 1;
	}
	/* If we're pretty sure the backing resource is effectively
	 * immutable, skip checksumming, it's a waste of time.  Except
	 * if the mapping is mutable, for example the rw data segment
	 * of a system library, then it's interesting. */
	may_diverge = (should_copy_mmap_region(info->name, &st,
					       info->prot, info->flags,
					       DONT_WARN_SHARED_WRITEABLE)
		       || (PROT_WRITE & info->prot));
	debug("%s '%s'",
	      may_diverge ? "CHECKSUMMING" : "  skipping", info->name);
	return may_diverge;
}

/**
 * Either create and store checksums for each segment mapped in |t|'s
 * address space, or validate an existing computed checksum.  Behavior
 * is selected by |mode|.
 */
static void iterate_checksums(Task* t, ChecksumMode mode)
{
	struct checksum_iterator_data c;
	memset(&c, sizeof(c), 0);
	char filename[PATH_MAX];
	const char* fmode = (STORE_CHECKSUMS == mode) ? "w" : "r";

	c.mode = mode;
	snprintf(filename, sizeof(filename) - 1, "%s/%d_%d",
		 get_trace_path(), get_global_time(), t->rec_tid);
	c.checksums_file = fopen(filename, fmode);

	iterate_memory_map(t, checksum_iterator, &c,
			   checksum_segment_filter, NULL);

	fclose(c.checksums_file);
}

int should_checksum(Task* t, int event, int state, int global_time)
{
	int checksum = rr_flags()->checksum;
	int is_syscall_exit = (event >= 0 && state == STATE_SYSCALL_EXIT);

#if defined(FIRST_INTERESTING_EVENT)
	if (is_syscall_exit
	    && FIRST_INTERESTING_EVENT <= global_time
	    && global_time <= LAST_INTERESTING_EVENT) {
		return 1;
	}
	if (global_time > LAST_INTERESTING_EVENT) {
		return 0;
	}
#endif
	if (CHECKSUM_NONE == checksum) {
		return 0;
	}
	if (CHECKSUM_ALL == checksum) {
		return 1;
	}
	if (CHECKSUM_SYSCALL == checksum) {
		return is_syscall_exit;
	}
	/* |checksum| is a global time point. */
	return checksum <= global_time;
}

void checksum_process_memory(Task* t)
{
	/* flush all files in case we start replaying while still
	 * recording */
	flush_trace_files();

	iterate_checksums(t, STORE_CHECKSUMS);
}

void validate_process_memory(Task* t)
{
	iterate_checksums(t, VALIDATE_CHECKSUMS);
}

void cleanup_code_injection(struct current_state_buffer* buf)
{
	free(buf->code_buffer);
	free(buf);
}

void copy_syscall_arg_regs(struct user_regs_struct* to,
			   const struct user_regs_struct* from)
{
	to->ebx = from->ebx;
	to->ecx = from->ecx;
	to->edx = from->edx;
	to->esi = from->esi;
	to->edi = from->edi;
	to->ebp = from->ebp;
}

void record_struct_msghdr(Task* t, struct msghdr* child_msghdr)
{
	struct msghdr* msg =
		(struct msghdr*)read_child_data(t, sizeof(*msg),
						(byte*)child_msghdr);
	struct iovec* iov;

	/* Record the entire struct, because some of the direct fields
	 * are written as inoutparams. */
	record_child_data(t, sizeof(*child_msghdr), (byte*)child_msghdr);
	record_child_data(t, msg->msg_namelen, (byte*)msg->msg_name);

	assert("TODO: record more than 1 iov" && msg->msg_iovlen == 1);

	record_child_data(t, sizeof(struct iovec), (byte*)msg->msg_iov);
	iov = (struct iovec*)read_child_data(t, sizeof(struct iovec), (byte*)msg->msg_iov);
	record_child_data(t, iov->iov_len, (byte*)iov->iov_base);

	record_child_data(t, msg->msg_controllen, (byte*)msg->msg_control);

	free(iov);
	free(msg);
}

void record_struct_mmsghdr(Task* t, struct mmsghdr* child_mmsghdr)
{
	/* struct mmsghdr has an inline struct msghdr as its first
	 * field, so it's OK to make this "cast". */
	record_struct_msghdr(t, (struct msghdr*)child_mmsghdr);
	/* We additionally have to record the outparam number of
	 * received bytes. */
	record_child_data(t, sizeof(child_mmsghdr->msg_len),
			  (byte*)&child_mmsghdr->msg_len);
}

void restore_struct_msghdr(Task* t, struct msghdr* child_msghdr)
{
	/* TODO: with above, generalize for arbitrary msghdr. */
	const int num_emu_args = 5;
	int i;

	for (i = 0; i < num_emu_args; ++i) {
		set_child_data(t);
	}
}

void restore_struct_mmsghdr(Task* t, struct mmsghdr* child_mmsghdr)
{
	restore_struct_msghdr(t, (struct msghdr*)child_mmsghdr);
	set_child_data(t);
}

int is_desched_event_syscall(Task* t,
			     const struct user_regs_struct* regs)
{
	return (SYS_ioctl == regs->orig_eax
		&& (t->desched_fd_child == regs->ebx
		    || t->desched_fd_child == REPLAY_DESCHED_EVENT_FD));
}

int is_arm_desched_event_syscall(Task* t,
				 const struct user_regs_struct* regs)
{
	return (is_desched_event_syscall(t, regs)
		&& PERF_EVENT_IOC_ENABLE == regs->ecx);
}

int is_disarm_desched_event_syscall(Task* t,
				    const struct user_regs_struct* regs)
{
	return (is_desched_event_syscall(t, regs)
		&& PERF_EVENT_IOC_DISABLE == regs->ecx);
}

bool is_now_contended_pi_futex(Task* t, byte* futex, uint32_t* next_val)
{
	static_assert(sizeof(uint32_t) == sizeof(long),
		      "Sorry, need to add Task::read_int()");
	uint32_t val = t->read_word(futex);
	pid_t owner_tid = (val & FUTEX_TID_MASK);
	bool now_contended = (owner_tid != 0 && owner_tid != t->rec_tid
			      && !(val & FUTEX_WAITERS));
	if (now_contended) {
		debug("[%d] %d: futex %p is %ld, so WAITERS bit will be set",
		      get_global_time(), t->tid, futex, val);
		*next_val = (owner_tid & FUTEX_TID_MASK) | FUTEX_WAITERS;
	}
	return now_contended;
}

int default_action(int sig)
{
	if (SIGRTMIN <= sig && sig <= SIGRTMAX) {
		return TERMINATE;
	}
	switch (sig) {
		/* TODO: SSoT for signal defs/semantics. */
#define CASE(_sig, _act) case SIG## _sig: return _act
	CASE(HUP, TERMINATE);
	CASE(INT, TERMINATE);
	CASE(QUIT, DUMP_CORE);
	CASE(ILL, DUMP_CORE);
	CASE(ABRT, DUMP_CORE);
	CASE(FPE, DUMP_CORE);
	CASE(KILL, TERMINATE);
	CASE(SEGV, DUMP_CORE);
	CASE(PIPE, TERMINATE);
	CASE(ALRM, TERMINATE);
	CASE(TERM, TERMINATE);
	CASE(USR1, TERMINATE);
	CASE(USR2, TERMINATE);
	CASE(CHLD, IGNORE);
	CASE(CONT, CONTINUE);
	CASE(STOP, STOP);
	CASE(TSTP, STOP);
	CASE(TTIN, STOP);
	CASE(TTOU, STOP);
	CASE(BUS, DUMP_CORE);
	/*CASE(POLL, TERMINATE);*/
	CASE(PROF, TERMINATE);
	CASE(SYS, DUMP_CORE);
	CASE(TRAP, DUMP_CORE);
	CASE(URG, IGNORE);
	CASE(VTALRM, TERMINATE);
	CASE(XCPU, DUMP_CORE);
	CASE(XFSZ, DUMP_CORE);
	/*CASE(IOT, DUMP_CORE);*/
	/*CASE(EMT, TERMINATE);*/
	CASE(STKFLT, TERMINATE);
	CASE(IO, TERMINATE);
	CASE(PWR, TERMINATE);
	/*CASE(LOST, TERMINATE);*/
	CASE(WINCH, IGNORE);
	default:
		fatal("Unknown signal %d", sig);
#undef CASE
	}
}

bool possibly_destabilizing_signal(Task* t, int sig)
{
	sig_handler_t disp = t->signal_disposition(sig);
	int action = default_action(sig);
	// If the diposition is IGN or user handler, then the signal
	// won't be fatal.  So we only need to check for DFL.
	return SIG_DFL == disp && (DUMP_CORE == action || TERMINATE == action);
}

static bool has_fs_name(const char* path)
{
	struct stat dummy;
	return 0 == stat(path, &dummy);
}

static bool is_tmp_file(const char* path)
{
	struct statfs sfs;
	statfs(path, &sfs);
	return TMPFS_MAGIC == sfs.f_type;
}

bool should_copy_mmap_region(const char* filename, const struct stat* stat,
			     int prot, int flags,
			     int warn_shared_writeable)
{
	bool private_mapping = (flags & MAP_PRIVATE);

	// TODO: handle mmap'd files that are unlinked during
	// recording.
	if (!has_fs_name(filename)) {
		debug("  copying unlinked file");
		return true;
	}
	if (is_tmp_file(filename)) {
		debug("  copying file on tmpfs");
		return true;
	}
	if (private_mapping && (prot & PROT_EXEC)) {
		/* We currently don't record the images that we
		 * exec(). Since we're being optimistic there (*cough*
		 * *cough*), we're doing no worse (in theory) by being
		 * optimistic about the shared libraries too, most of
		 * which are system libraries. */
		debug("  (no copy for +x private mapping %s)", filename);
		return false;
	}
	if (private_mapping && (0111 & stat->st_mode)) {
		/* A private mapping of an executable file usually
		 * indicates mapping data sections of object files.
		 * Since we're already assuming those change very
		 * infrequently, we can avoid copying the data
		 * sections too. */
		debug("  (no copy for private mapping of +x %s)", filename);
		return false;
	}

	// TODO: using "can the euid of the rr process write this
	// file" as an approximation of whether the tracee can write
	// the file.  If the tracee is messing around with
	// set*[gu]id(), the real answer may be different.
	bool can_write_file = (0 == access(filename, W_OK));

	if (!can_write_file && 0 == stat->st_uid) {
		assert(!(prot & PROT_WRITE));
		/* Mapping a file owned by root: we don't care if this
		 * was a PRIVATE or SHARED mapping, because unless the
		 * program is disastrously buggy or unlucky, the
		 * mapping is effectively PRIVATE.  Bad luck can come
		 * from this program running during a system update,
		 * or a user being added, which is probably less
		 * frequent than even system updates.
		 *
		 * XXX what about the fontconfig cache files? */
		debug("  (no copy for root-owned %s)", filename);
		return false;
	}
	if (private_mapping) {
		/* Some programs (at least Firefox) have been observed
		 * to use cache files that are expected to be
		 * consistent and unchanged during the bulk of
		 * execution, but may be destroyed or mutated at
		 * shutdown in preparation for the next session.  We
		 * don't otherwise know what to do with private
		 * mappings, so err on the safe side.
		 *
		 * TODO: could get into dirty heuristics here like
		 * trying to match "cache" in the filename ...	 */
		debug("  copying private mapping of non-system -x %s",
		      filename);
		return true;
	}
	if (!(0222 & stat->st_mode)) {
		/* We couldn't write the file because it's read only.
		 * But it's not a root-owned file (therefore not a
		 * system file), so it's likely that it could be
		 * temporary.  Copy it. */
		debug("  copying read-only, non-system file");
		return true;
	}
	if (!can_write_file) {
		/* mmap'ing another user's (non-system) files?  Highly
		 * irregular ... */
		fatal("Unhandled mmap %s(prot:%x%s); uid:%d mode:%o",
		      filename, prot, (flags & MAP_SHARED) ? ";SHARED" : "",
		      stat->st_uid, stat->st_mode);
	}
	/* Shared mapping that we can write.  Should assume that the
	 * mapping is likely to change. */
	debug("  copying writeable SHARED mapping %s", filename);
	if (PROT_WRITE | prot) {
#ifndef DEBUGTAG
		if (warn_shared_writeable)
#endif
		log_warn("%s is SHARED|WRITEABLE; that's not handled correctly yet. Optimistically hoping it's not written by programs outside the rr tracee tree.",
			 filename);
	}
	return true;
}

int create_shmem_segment(const char* name, size_t num_bytes, int cloexec)
{
	char path[PATH_MAX];
	snprintf(path, sizeof(path) - 1, "%s/%s", SHMEM_FS, name);

	int fd = open(path, O_CREAT | O_EXCL | O_RDWR | cloexec, 0600);
	if (0 > fd) {
		fatal("Failed to create shmem segment %s", path);
	}
	/* Remove the fs name so that we don't have to worry about
	 * cleaning up this segment in error conditions. */
	unlink(path);
	resize_shmem_segment(fd, num_bytes);

	debug("created shmem segment %s", path);
	return fd;
}

void resize_shmem_segment(int fd, size_t num_bytes)
{
	if (ftruncate(fd, num_bytes)) {
		fatal("Failed to resize shmem to %d", num_bytes);
	}
}

void prepare_remote_syscalls(Task* t,
			     struct current_state_buffer* state)
{
	/* Save current state of |t|. */
	memset(state, 0, sizeof(*state));
	state->pid = t->tid;
	t->get_regs(&state->regs);
	state->code_size = sizeof(syscall_insn);
	state->start_addr = (byte*)state->regs.eip;
	state->code_buffer =
		(byte*)read_child_data(t, state->code_size, state->start_addr);

	/* Inject phony syscall instruction. */
	write_child_data(t, state->code_size, state->start_addr,
			 syscall_insn);
}

void* push_tmp_mem(Task* t, struct current_state_buffer* state,
		   const byte* mem, ssize_t num_bytes,
		   struct restore_mem* restore)
{
	restore->len = num_bytes;
	restore->saved_sp = (byte*)state->regs.esp;

	state->regs.esp -= restore->len;
	t->set_regs(state->regs);
	restore->addr = (byte*)state->regs.esp;

	restore->data = (byte*)read_child_data(t, restore->len, restore->addr);

	write_child_data(t, restore->len, restore->addr, mem);

	return restore->addr;
}

void* push_tmp_str(Task* t, struct current_state_buffer* state,
		   const char* str, struct restore_mem* restore)
{
	return push_tmp_mem(t, state,
			    (const byte*)str, strlen(str) + 1/*null byte*/,
			    restore);
}

void pop_tmp_mem(Task* t, struct current_state_buffer* state,
		 struct restore_mem* mem)
{
	assert(mem->saved_sp == (byte*)state->regs.esp + mem->len);

	write_child_data(t, mem->len, mem->addr, mem->data);
	free(mem->data);

	state->regs.esp += mem->len;
	t->set_regs(state->regs);
}

// XXX this is probably dup'd somewhere else
static void advance_syscall(Task* t)
{
	t->cont_syscall();

	/* Skip past a seccomp trace, if we happened to see one. */
	if (t->is_ptrace_seccomp_event()) {
		t->cont_syscall();
	}
	assert(t->ptrace_event() == 0);
}

long remote_syscall(Task* t, struct current_state_buffer* state,
		    int wait, int syscallno,
		    long a1, long a2, long a3, long a4, long a5, long a6)
{
	pid_t tid = t->tid;
	struct user_regs_struct callregs;

	assert(tid == state->pid);

	/* Prepare syscall arguments. */
	memcpy(&callregs, &state->regs, sizeof(callregs));
	callregs.eax = syscallno;
	callregs.ebx = a1;
	callregs.ecx = a2;
	callregs.edx = a3;
	callregs.esi = a4;
	callregs.edi = a5;
	callregs.ebp = a6;
	t->set_regs(callregs);

	advance_syscall(t);

	t->get_regs(&callregs);
	assert_exec(t, callregs.orig_eax == syscallno,
		    "Should be entering %s, but instead at %s",
		    syscallname(syscallno), syscallname(callregs.orig_eax));

	/* Start running the syscall. */
	t->cont_syscall_nonblocking();
	if (WAIT == wait) {
		return wait_remote_syscall(t, state, syscallno);
	}
	return 0;
}

long wait_remote_syscall(Task* t, struct current_state_buffer* state,
			 int syscallno)
{
	struct user_regs_struct regs;
	/* Wait for syscall-exit trap. */
	t->wait();

	t->get_regs(&regs);
	assert_exec(t, regs.orig_eax == syscallno,
		    "Should be entering %s, but instead at %s",
		    syscallname(syscallno), syscallname(regs.orig_eax));

	return regs.eax;
}

void finish_remote_syscalls(Task* t,
			    struct current_state_buffer* state)
{
	pid_t tid = t->tid;

	assert(tid == state->pid);

	/* Restore stomped instruction. */
	write_child_data(t, state->code_size, state->start_addr,
			 state->code_buffer);
	free(state->code_buffer);

	/* Restore stomped registers. */
	t->set_regs(state->regs);
}

/**
 * Share |fd| to the other side of |sock|.
 */
static void send_fd(int fd, int sock)
{
	struct msghdr msg;
	int dummy_fd = 0;
	struct iovec data;
	struct cmsghdr* cmsg;
	char cmsgbuf[CMSG_SPACE(sizeof(int))];

	memset(&msg, 0, sizeof(msg));

	/* We must always send the same value to the child so that
	 * nondeterministic values, like fd numbers in this process,
	 * don't leak into its address space. */
	data.iov_base = &dummy_fd;
	data.iov_len = sizeof(dummy_fd);
	msg.msg_iov = &data;
	msg.msg_iovlen = 1;

	msg.msg_control = cmsgbuf;
	msg.msg_controllen = CMSG_LEN(sizeof(int));

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(int*)CMSG_DATA(cmsg) = fd;

	if (0 >= sendmsg(sock, &msg, 0)) {
		fatal("Failed to send fd");
	}
}

/**
 * Block until receiving an fd the other side of |sock| sent us, then
 * return the fd (valid in this address space).  Optionally return the
 * remote fd number that was shared to us in |remote_fdno|.
 */
static int recv_fd(int sock, int* remote_fdno)
{
	struct msghdr msg;
	int fd, remote_fd;
	struct iovec data;
	struct cmsghdr* cmsg;
	char cmsgbuf[CMSG_SPACE(sizeof(int))];

	memset(&msg, 0, sizeof(msg));

	data.iov_base = &remote_fd;
	data.iov_len = sizeof(remote_fd);
	msg.msg_iov = &data;
	msg.msg_iovlen = 1;

	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	if (0 >= recvmsg(sock, &msg, 0)) {
		fatal("Failed to receive fd");
	}

	cmsg = CMSG_FIRSTHDR(&msg);
	assert(cmsg->cmsg_level == SOL_SOCKET
	       && cmsg->cmsg_type == SCM_RIGHTS);

	fd = *(int*)CMSG_DATA(cmsg);
	if (remote_fdno) {
		*remote_fdno = remote_fd;
	}

	return fd;
}

static void write_socketcall_args(Task* t,
				  struct socketcall_args* child_args_vec,
				  long arg1, long arg2, long arg3)
{
	struct socketcall_args args = { { arg1, arg2, arg3 } };
	write_child_data(t, sizeof(args), (byte*)child_args_vec, (byte*)&args);
}

static void* init_syscall_buffer(Task* t, struct current_state_buffer* state,
				 struct rrcall_init_buffers_params* args,
				 void* map_hint, int share_desched_fd)
{
	pid_t tid = t->tid;
	char shmem_name[PATH_MAX];
	struct sockaddr_un addr;
	long child_ret;
	int listen_sock, sock, child_sock;
	int shmem_fd, child_shmem_fd;
	void* map_addr;
	byte* child_map_addr;
	void* tmp;
	int zero = 0;

	t->traced_syscall_ip = args->traced_syscall_ip;
	t->untraced_syscall_ip = args->untraced_syscall_ip;
	format_syscallbuf_shmem_path(tid, shmem_name);
	/* NB: the sockaddr prepared by the child uses the recorded
	 * tid, so always must here. */
	prepare_syscallbuf_socket_addr(&addr, t->rec_tid);

	/* Create the segment we'll share with the tracee. */
	shmem_fd = create_shmem_segment(shmem_name, SYSCALLBUF_BUFFER_SIZE);

	/* Bind the server socket, but don't start listening yet. */
	listen_sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (::bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr))) {
		fatal("Failed to bind listen socket");
	}
	if (listen(listen_sock, 1)) {
		fatal("Failed to mark listening for listen socket");
	}

	/* Initiate tracee connect(), but don't wait for it to
	 * finish. */
	write_socketcall_args(t, args->args_vec, AF_UNIX, SOCK_STREAM, 0);
	child_sock = remote_syscall2(t, state, SYS_socketcall,
				     SYS_SOCKET, args->args_vec);
	if (0 > child_sock) {
		errno = -child_sock;
		fatal("Failed to create child socket");
	}
	write_socketcall_args(t, args->args_vec, child_sock,
			      (uintptr_t)args->sockaddr,
			      sizeof(*args->sockaddr));
	remote_syscall(t, state, DONT_WAIT, SYS_socketcall,
		       SYS_CONNECT, (uintptr_t)args->args_vec, 0, 0, 0, 0);
	/* Now the child is waiting for us to accept it. */

	/* Accept the child's connection and finish its syscall.
	 *
	 * XXX could be really anal and check credentials of
	 * connecting endpoint ... */
	sock = accept(listen_sock, NULL, NULL);
	if ((child_ret = wait_remote_syscall(t, state, SYS_socketcall))) {
		errno = -child_ret;
		fatal("Failed to connect() in tracee");
	}
	/* Socket name not needed anymore. */
	unlink(addr.sun_path);

	if (SHARE_DESCHED_EVENT_FD == share_desched_fd) {
		/* Pull the puppet strings to have the child share its
		 * desched counter with us.  Similarly to above, we
		 * DONT_WAIT on the call to finish, since it's likely
		 * not defined whether the sendmsg() may block on our
		 * recvmsg()ing what the tracee sent us (in which case
		 * we would deadlock with the tracee). */
		write_socketcall_args(t, args->args_vec, child_sock,
				      (uintptr_t)args->msg, 0);
		remote_syscall(t, state, DONT_WAIT, SYS_socketcall,
			       SYS_SENDMSG, (uintptr_t)args->args_vec,
			       0, 0, 0, 0);
		/* Child may be waiting on our recvmsg(). */

		/* Read the shared fd and finish the child's syscall. */
		t->desched_fd = recv_fd(sock, &t->desched_fd_child);
		if (0 >= wait_remote_syscall(t, state, SYS_socketcall)) {
			errno = -child_ret;
			fatal("Failed to sendmsg() in tracee");
		}
	} else {
		t->desched_fd_child = REPLAY_DESCHED_EVENT_FD;
	}

	/* Share the shmem fd with the child.  It's ok to reuse the
	 * |child_msg| buffer. */
	send_fd(shmem_fd, sock);
	write_socketcall_args(t, args->args_vec, child_sock,
			      (uintptr_t)args->msg, 0);
	child_ret = remote_syscall2(t, state, SYS_socketcall,
				    SYS_RECVMSG, args->args_vec);
	if (0 >= child_ret) {
		errno = -child_ret;
		fatal("Failed to recvmsg() shared fd in tracee");
	}

	/* Get the newly-allocated fd. */
	tmp = read_child_data(t, sizeof(child_shmem_fd), (byte*)args->fdptr);
	child_shmem_fd = *(int*)tmp;
	free(tmp);

	/* Zero out the child buffers we use here.  They contain
	 * "real" fds, which in general will not be the same across
	 * record/replay. */
	write_socketcall_args(t, args->args_vec, 0, 0, 0);
	write_child_data(t, sizeof(zero), (byte*)args->fdptr, (byte*)&zero);

	/* Socket magic is now done. */
	close(listen_sock);
	close(sock);
	remote_syscall1(t, state, SYS_close, child_sock);

	/* Map the segment in our address space and in the
	 * tracee's. */
	t->num_syscallbuf_bytes = SYSCALLBUF_BUFFER_SIZE;
	int prot = PROT_READ | PROT_WRITE;
	int flags = MAP_SHARED;
	off64_t offset_pages = 0;
	if ((void*)-1 == (map_addr = mmap(NULL, t->num_syscallbuf_bytes,
					  prot, flags,
					  shmem_fd, offset_pages))) {
		fatal("Failed to mmap shmem region");
	}
	child_map_addr = (byte*)remote_syscall6(t, state, SYS_mmap2,
						map_hint,
						t->num_syscallbuf_bytes,
						prot, flags, child_shmem_fd,
						offset_pages);
	t->syscallbuf_child = args->syscallbuf_ptr = child_map_addr;
	t->syscallbuf_hdr = (struct syscallbuf_hdr*)map_addr;
	/* No entries to begin with. */
	memset(t->syscallbuf_hdr, 0, sizeof(*t->syscallbuf_hdr));

	t->vm()->map((const byte*)child_map_addr, t->num_syscallbuf_bytes,
		     prot, flags, page_size() * offset_pages,
		     MappableResource::syscallbuf(t->rec_tid, shmem_fd));

	close(shmem_fd);
	remote_syscall1(t, state, SYS_close, child_shmem_fd);

	return child_map_addr;
}

void* init_buffers(Task* t, void* map_hint, int share_desched_fd)
{
	struct current_state_buffer state;
	byte* child_args;
	struct rrcall_init_buffers_params* args;
	void* child_map_addr = NULL;

	/* NB: the tracee can't be interrupted with a signal while
	 * we're processing the rrcall, because it's masked off all
	 * signals. */

	prepare_remote_syscalls(t, &state);
	/* Arguments to the rrcall. */
	child_args = (byte*)state.regs.ebx;
	args = (struct rrcall_init_buffers_params*)
	       read_child_data(t, sizeof(*args), child_args);

	child_map_addr = init_syscall_buffer(t, &state, args,
					     map_hint, share_desched_fd);

	/* Return the mapped buffers to the child. */
	write_child_data(t, sizeof(*args), child_args, (byte*)args);
	free(args);

	/* The tracee doesn't need this addr returned, because it's
	 * already written to the inout |args| param, but we stash it
	 * away in the return value slot so that we can easily check
	 * that we map the segment at the same addr during replay. */
	state.regs.eax = (uintptr_t)child_map_addr;
	t->inited_syscallbuf();
	finish_remote_syscalls(t, &state);

	return child_map_addr;
}

void destroy_buffers(Task* t, int flags)
{
	// NB: we have to pay all this complexity here because glibc
	// makes its SYS_exit call through an inline int $0x80 insn,
	// instead of going through the vdso.  There may be a deep
	// reason for why it does that, but if it starts going through
	// the vdso in the future, this code can be eliminated in
	// favor of a *much* simpler vsyscall SYS_exit hook in the
	// preload lib.

	if (!(DESTROY_ALREADY_AT_EXIT_SYSCALL & flags)) {
		// Advance the tracee into SYS_exit so that it's at a
		// known state that we can manipulate it from.
		advance_syscall(t);
	}

	struct user_regs_struct exit_regs;
	t->get_regs(&exit_regs);
	assert_exec(t, SYS_exit == exit_regs.orig_eax,
		    "Tracee should have been at exit, but instead at %s",
		    syscallname(exit_regs.orig_eax));

	// The tracee is at the entry to SYS_exit, but hasn't started
	// the call yet.  We can't directly start injecting syscalls
	// because the tracee is still in the kernel.  And obviously,
	// if we finish the SYS_exit syscall, the tracee isn't around
	// anymore.
	//
	// So hijack this SYS_exit call and rewrite it into a harmless
	// one that we can exit successfully, SYS_gettid here (though
	// that choice is arbitrary).
	exit_regs.orig_eax = SYS_gettid;
	t->set_regs(exit_regs);
	// This exits the hijacked SYS_gettid.  Now the tracee is
	// ready to do our bidding.
	advance_syscall(t);

	// Restore these regs to what they would have been just before
	// the tracee trapped at SYS_exit.  When we've finished
	// cleanup, we'll restart the SYS_exit call.
	exit_regs.orig_eax = -1;
	exit_regs.eax = SYS_exit;
	exit_regs.eip -= sizeof(syscall_insn);

	byte insn[sizeof(syscall_insn)];
	t->read_bytes((const byte*)exit_regs.eip, insn);
	assert_exec(t, !memcmp(insn, syscall_insn, sizeof(insn)),
		    "Tracee should have entered through int $0x80.");

	struct current_state_buffer state;
	prepare_remote_syscalls(t, &state);

	// Do the actual buffer and fd cleanup.
	remote_syscall2(t, &state, SYS_munmap,
			t->scratch_ptr, t->scratch_size);
	t->vm()->unmap(t->scratch_ptr, t->scratch_size);
	if (t->syscallbuf_child) {
		remote_syscall2(t, &state, SYS_munmap,
				t->syscallbuf_child, t->num_syscallbuf_bytes);
		t->vm()->unmap(t->syscallbuf_child, t->num_syscallbuf_bytes);
		remote_syscall1(t, &state, SYS_close, t->desched_fd_child);
	}

	finish_remote_syscalls(t, &state);

	// Prepare to restart the SYS_exit call.
	t->set_regs(exit_regs);
	if (DESTROY_NEED_EXIT_SYSCALL_RESTART & flags) {
		advance_syscall(t);
	}
}

static const byte vsyscall_impl[] = {
    0x51,                       /* push %ecx */
    0x52,                       /* push %edx */
    0x55,                       /* push %ebp */
    0x89, 0xe5,                 /* mov %esp,%ebp */
    0x0f, 0x34,                 /* sysenter */
    0x90,                       /* nop */
    0x90,                       /* nop */
    0x90,                       /* nop */
    0x90,                       /* nop */
    0x90,                       /* nop */
    0x90,                       /* nop */
    0x90,                       /* nop */
    0xcd, 0x80,                 /* int $0x80 */
    0x5d,                       /* pop %ebp */
    0x5a,                       /* pop %edx */
    0x59,                       /* pop %ecx */
    0xc3,                       /* ret */
};

/**
 * Return true iff |addr| points to a known |__kernel_vsyscall()|
 * implementation.
 */
static bool is_kernel_vsyscall(Task* t, const byte* addr)
{
	byte impl[sizeof(vsyscall_impl)];
	t->read_bytes(addr, impl);
	for (size_t i = 0; i < sizeof(vsyscall_impl); ++i) {
		if (vsyscall_impl[i] != impl[i]) {
			log_warn("Byte %d of __kernel_vsyscall should be 0x%x, but is 0x%x",
				 i, vsyscall_impl[i], impl[i]);
			return false;
		}
	}
	return true;
}

/**
 * Return the address of a recognized |__kernel_vsyscall()|
 * implementation in |t|'s address space.
 */
static const byte* locate_and_verify_kernel_vsyscall(Task* t)
{
	const byte* vdso_start = t->vm()->vdso().start;
	// __kernel_vsyscall() has been observed to be mapped at the
	// following offsets from the vdso start address.  We'll try
	// to recognize a known __kernel_vsyscall() impl at any of
	// these offsets.
	const ssize_t known_offsets[] = {
		0x414,		// x86 native kernel ca. 3.12.10-300
		0x420		// x86 process on x64 kernel
	};
	for (size_t i = 0; i < ALEN(known_offsets); ++i) {
		const byte* addr = vdso_start + known_offsets[i];
		if (is_kernel_vsyscall(t, addr)) {
			return addr;
		}
	}
	return nullptr;
}

// NBB: the placeholder bytes in |struct insns_template| below must be
// kept in sync with this.
static const byte vsyscall_monkeypatch[] = {
	0x50,                         // push %eax
	0xb8, 0x00, 0x00, 0x00, 0x00, // mov $_vsyscall_hook_trampoline, %eax
	// The immediate param of the |mov| is filled in dynamically
	// by the template mechanism below.  The NULL here is a
	// placeholder.
	0xff, 0xe0,		// jmp *%eax
};

struct insns_template {
	// NBB: |vsyscall_monkeypatch| must be kept in sync with these
	// placeholder bytes.
	byte push_eax_insn;
	byte mov_vsyscall_hook_trampoline_eax_insn;
	void* vsyscall_hook_trampoline;
} __attribute__((packed));

/**
 * Monkeypatch |t|'s |__kernel_vsyscall()| helper to jump to
 * |vsyscall_hook_trampoline|.
 */
static void monkeypatch(Task* t, const byte* kernel_vsyscall,
			void* vsyscall_hook_trampoline)
{
	union {
		byte bytes[sizeof(vsyscall_monkeypatch)];
		struct insns_template insns;
	} __attribute__((packed)) patch;
	// Write the basic monkeypatch onto to the template, except
	// for the (dynamic) $vsyscall_hook_trampoline address.
	memcpy(patch.bytes, vsyscall_monkeypatch, sizeof(patch.bytes));
	// (Try to catch out-of-sync |vsyscall_monkeypatch| and
	// |struct insns_template|.)
	assert(nullptr == patch.insns.vsyscall_hook_trampoline);
	patch.insns.vsyscall_hook_trampoline = vsyscall_hook_trampoline;

	t->write_bytes(kernel_vsyscall, patch.bytes);
	debug("monkeypatched __kernel_vsyscall to jump to %p",
	      vsyscall_hook_trampoline);
}

void monkeypatch_vdso(Task* t)
{
	const byte* kernel_vsyscall = locate_and_verify_kernel_vsyscall(t);
	if (!kernel_vsyscall) {
		fatal(
"Failed to monkeypatch vdso: your __kernel_vsyscall() wasn't recognized.\n"
"    Syscall buffering is now effectively disabled.  If you're OK with\n"
"    running rr without syscallbuf, then run the recorder passing the\n"
"    --no-syscall-buffer arg.\n"
"    If you're *not* OK with that, file an issue.");
	}

	debug("__kernel_vsyscall is %p", kernel_vsyscall);

	assert_exec(t, 1 == t->vm()->task_set().size(),
		    "TODO: monkeypatch multithreaded process");

	// NB: the tracee can't be interrupted with a signal while
	// we're processing the rrcall, because it's masked off all
	// signals.
	struct user_regs_struct regs;
	t->get_regs(&regs);

	void* vsyscall_hook_trampoline = (void*)regs.ebx;
	// Luckily, linux is happy for us to scribble directly over
	// the vdso mapping's bytes without mprotecting the region, so
	// we don't need to prepare remote syscalls here.
	monkeypatch(t, kernel_vsyscall, vsyscall_hook_trampoline);

	regs.eax = 0;
	t->set_regs(regs);
}
