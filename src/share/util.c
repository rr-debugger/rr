#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <libdis.h>
#include <string.h>
#include <stdlib.h>

#include <sys/signal.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>

#include "util.h"

#include "../share/dbg.h"
#include "../share/ipc.h"
#include "../share/sys.h"
#include "../share/types.h"

static char* syscall_str[350] = { "restart_syscall", "exit", "fork", "read", "write", "open", "close", "waitpid", "creat", "link", "unlink", "execve", "chdir", "time", "mknod", "chmod", "lchown",
		"break", "oldstat", "lseek", "getpid", "mount", "umount", "setuid", "getuid", "stime", "ptrace", "alarm", "oldfstat", "pause", "utime", "stty", "gtty", "access", "nice", "ftime", "sync",
		"kill", "rename", "mkdir", "rmdir", "dup", "pipe", "times", "prof", "brk", "setgid", "getgid", "signal", "geteuid", "getegid", "acct", "umount2", "lock", "ioctl", "fcntl", "mpx", "setpgid",
		"ulimit", "oldolduname", "umask", "chroot", "ustat", "dup2", "getppid", "getpgrp", "setsid", "sigaction", "sgetmask", "ssetmask", "setreuid", "setregid", "sigsuspend", "sigpending",
		"sethostname", "setrlimit", "getrlimit", "getrusage", "gettimeofday", "settimeofday", "getgroups", "setgroups", "select", "symlink", "oldlstat", "readlink", "uselib", "swapon", "reboot",
		"readdir", "mmap", "munmap", "truncate", "ftruncate", "fchmod", "fchown", "getpriority", "setpriority", "profil", "statfs", "fstatfs", "ioperm", "socketcall", "syslog", "setitimer",
		"getitimer", "stat", "lstat", "fstat", "olduname", "iopl", "vhangup", "idle", "vm86old", "wait4", "swapoff", "sysinfo", "ipc", "fsync", "sigreturn", "clone", "setdomainname", "uname",
		"modify_ldt", "adjtimex", "mprotect", "sigprocmask", "create_module", "init_module", "delete_module", "get_kernel_syms", "quotactl", "getpgid", "fchdir", "bdflush", "sysfs", "personality",
		"afs_syscall", "setfsuid", "setfsgid", "_llseek", "getdents", "_newselect", "flock", "msync", "readv", "writev", "getsid", "fdatasync", "_sysctl", "mlock", "munlock", "mlockall", "munlockall",
		"sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler", "sched_yield", "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval", "nanosleep",
		"mremap", "setresuid", "getresuid", "vm86", "query_module", "poll", "nfsservctl", "setresgid", "getresgid", "prctl", "rt_sigreturn", "rt_sigaction", "rt_sigprocmask", "rt_sigpending",
		"rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigsuspend", "pread64", "pwrite64", "chown", "getcwd", "capget", "capset", "sigaltstack", "sendfile", "getpmsg", /* some people actually want streams */
		"putpmsg", /* some people actually want streams */
		"vfork", "ugetrlimit", /* SuS compliant getrlimit */
		"mmap2", "truncate64", "ftruncate64", "stat64", "lstat64", "fstat64", "lchown32", "getuid32", "getgid32", /* 200 */
		"geteuid32", "getegid32", "setreuid32", "setregid32", "getgroups32", "setgroups32", "fchown32", "setresuid32", "getresuid32", "setresgid32", "getresgid32", "chown32", "setuid32", "setgid32",
		"setfsuid32", "setfsgid32", "pivot_root", "mincore", "madvise", "madvise1", /* delete when C lib stub is removed */
		"getdents64", "fcntl64", "223 is unused", "gettid", "readahead", "setxattr", "lsetxattr", "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr",
		"removexatt", "lremovexattr", "fremovexattr", "tkill", "sendfile64", "futex", "sched_setaffinity", "sched_getaffinity", "set_thread_area", "get_thread_area", "io_setup", "io_destroy",
		"io_getevents", "io_submit", "io_cancel", "fadvise64" };

char* syscall_to_str(int syscall)
{
	assert(syscall < 350);
	return syscall_str[syscall];
}

int signal_pending(int status)
{
	if(status == 0x57f) {
		assert(1==0);
	}

	if (status == 0) {
		return 0;
	}

	/* we got a SIGTRAP from ptrace */
	if ((WSTOPSIG(status) & ~0x80) == SIGTRAP) {
		return 0;
	}

	/* we got a SIGSEGV from ptrace */
	if ((WSTOPSIG(status) & ~0x80) == SIGSEGV) {
		return SIGSEGV;
	}

	if (WSTOPSIG(status) == SIGCHLD) {
		return SIGCHLD;
	}

	return (WSTOPSIG(status) & ~0x80);

	/*int sig = WSTOPSIG(status) & ~0x80;

	 if (GET_PTRACE_EVENT(status)) {
	 printf("we got the ptrace event: %x\n",GET_PTRACE_EVENT(status));
	 }

	 return (sig == SIGTRAP) ? 0 : sig;*/
}

void print_register_file_tid(pid_t tid)
{
	struct user_regs_struct regs;
	read_child_registers(tid, &regs);
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

static unsigned long str2i(char* str, int base)
{
	char *endptr;
	unsigned long val = strtoul(str, &endptr, base);

	errno = 0;

	if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) || (errno != 0 && val == 0)) {
		perror("strtol");
		exit(EXIT_FAILURE);
	}

	if (endptr == str) {
		fprintf(stderr, "No digits were found\n");
		exit(EXIT_FAILURE);
	}

	return val;
}

void get_eip_info(pid_t tid)
{
	unsigned long eip = read_child_eip(tid);
	char buf[100];
	sprintf(buf, "/proc/%d/maps", tid);
	FILE* maps = sys_fopen(buf, "r");

	char* line = sys_malloc(512);

	unsigned long start, end;

	do {
		read_line(maps, line, 512, "maps");

		char addr[9];

		memcpy(addr, line, 8);
		addr[8] = '\0';
		start = str2i(addr, 16);

		memcpy(addr, line + 9, 8);
		addr[8] = '\0';

		end = str2i(addr, 16);
	} while (!((eip >= start) && (eip <= end)));

	char* tmp = sys_malloc(128);
	memcpy(tmp, line + 49, 128);
	fprintf(stderr, "file: %s", line);
	fprintf(stderr, "offset: %lx\n", eip - start);
	sys_free((void**) &tmp);
	sys_fclose(maps);
	sys_free((void**) &line);
}

char* get_inst(pid_t pid, int eip_offset, int* opcode_size)
{
	char* buf = NULL;
	unsigned long eip = read_child_eip(pid);
	unsigned char* inst = read_child_data_tid(pid, 128, eip + eip_offset);

	x86_init(opt_none, 0, 0);

	x86_insn_t x86_inst;

	unsigned int size = x86_disasm(inst, 128, 0, 0, &x86_inst);
	*opcode_size = size;

	buf = sys_malloc(128);
	if (size) {
		x86_format_insn(&x86_inst, buf, 128, att_syntax);
	} else {
		/* libdiasm does not support the entire instruction set -- pretty sad */
		strcpy(buf, "unknown");
	}
	sys_free((void**) &inst);
	x86_oplist_free(&x86_inst);
	x86_cleanup();

	return buf;
}

void print_inst(pid_t tid)
{
	int size;
	char* str = get_inst(tid, 0, &size);
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
		perror("error reading child memory maps\n");
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


/**
 * for printing syscall data on *replay* stage (as it uses the trace).
 * TODO: fix it so it will be suitable for both stages
 */
void print_syscall(struct context *ctx, struct trace *trace)
{

	int syscall = trace->recorded_regs.orig_eax;
	int state = trace->state;
	struct user_regs_struct r;
	read_child_registers(ctx->child_tid, &r);

	fprintf(stderr,"%u:%d:%d:", trace->global_time, ctx->rec_tid, ctx->trace.state);
	if (state == STATE_SYSCALL_ENTRY) {
		fprintf(stderr," event: %d",ctx->trace.stop_reason);
	}

	if (state == STATE_SYSCALL_EXIT) {
		switch (syscall) {

		/*  int access(const char *pathname, int mode); */
		case SYS_access:
		{
			char *str = read_child_str(ctx->child_tid, r.ebx);
			fprintf(stderr,"access(const char *pathname(%s), int mode(%lx))", str, r.ecx);
			free(str);
			break;
		}


		/* int clock_gettime(clockid_t clk_id, struct timespec *tp); */
		case SYS_clock_gettime:
		{
			fprintf(stderr,"clock_gettime(clockid_t clk_id(%lx), struct timespec *tp(%lx))", r.ebx, r.ecx);
			break;
		}

		/* int close(int fd) */
		case SYS_close:
		{
			fprintf(stderr,"close(int fd(%lx))", r.ebx);
			break;
		}

		/* int gettimeofday(struct timeval *tv, struct timezone *tz); */
		case SYS_gettimeofday:
		{
			fprintf(stderr,"gettimeofday(struct timeval *tv(%lx), struct timezone *tz(%lx))", r.ebx, r.ecx);
			break;
		}

		/* int fstat(int fd, struct stat *buf) */
		case SYS_fstat64:
		{
			fprintf(stderr,"fstat64(int fd(%lx), struct stat *buf(%lx))", r.ebx, r.ecx);
			break;
		}

		/* int futex(int *uaddr, int op, int val, const struct timespec *timeout, int *uaddr2, int val3); */
		case SYS_futex:
		{
			fprintf(stderr,"futex(int *uaddr(%lx), int op(%lx), int val(%lx), const struct timespec *timeout(%lx), int *uaddr2(%lx), int val3(%lx))", r.ebx, r.ecx, r.edx, r.esi, r.edi, r.ebp);
			break;
		}

		/* int ipc(unsigned int call, int first, int second, int third, void *ptr, long fifth); */
		case SYS_ipc:
		{
			fprintf(stderr,"ipc(unsigned int call(%lx), int first(%lx), int second(%lx), int third(%lx), void *ptr(%lx), long fifth(%lx)", r.ebx, r.ecx, r.edx, r.esi, r.edi, r.ebp);
			break;
		}

		/* int _llseek(unsigned int fd, unsigned long offset_high, unsigned long offset_low,
		 loff_t *result, unsigned int whence); */
		case SYS__llseek:
		{
			fprintf(stderr,"_llseek(unsigned int fd(%lx), unsigned long offset_high(%lx), unsigned long offset_low(%lx), loff_t *result(%lx), unsigned int whence(%lx)",
					r.ebx, r.ecx, r.edx, r.esi, r.edi);
			break;
		}

		/* void *mmap2(void *addr, size_t length, int prot,int flags, int fd, off_t pgoffset);*/
		case SYS_mmap2:
		{
			fprintf(stderr,"mmap2(void* addr(%lx), size_t len(%lx), int prot(%lx), int flags(%lx), int fd(%lx),off_t pgoffset(%lx)", r.ebx, r.ecx, r.edx, r.esi, r.edi, r.ebp);
			break;
		}

		/* int munmap(void *addr, size_t length) */
		case SYS_munmap:
		{
			fprintf(stderr,"munmap(void *addr(%lx), size_t length(%lx))", r.ebx, r.ecx);
			break;
		}

		/* int open(const char *pathname, int flags) */
		case SYS_open:
		{
			char *str = read_child_str(ctx->child_tid, r.ebx);
			fprintf(stderr,"open(const char *pathname(%s), int flags(%lx))", str, r.ecx);
			free(str);
			break;
		}

		/* int poll(struct pollfd *fds, nfds_t nfds, int timeout)*/
		case SYS_poll:
		{
			fprintf(stderr,"poll(struct pollfd *fds(%lx), nfds_t nfds(%lx), int timeout(%lx)", r.ebx, r.ecx, r.edx);
			break;
		}

		/* ssize_t read(int fd, void *buf, size_t count); */
		case SYS_read:
		{
			fprintf(stderr,"read(int fd(%lx), void *buf(%lx), size_t count(%lx)", r.ebx, r.ecx, r.edx);
			break;
		}

		/* int socketcall(int call, unsigned long *args) */
		case SYS_socketcall:
		{
			fprintf(stderr,"socketcall(int call(%ld), unsigned long *args(%lx))", r.ebx, r.ecx);
			break;
		}

		/* int stat(const char *path, struct stat *buf); */
		case SYS_stat64:
		{
			fprintf(stderr,"stat(const char *path(%s), struct stat *buf(%lx))", read_child_str(ctx->child_tid, r.ebx), r.ecx);
			break;
		}

		default:
		{
			fprintf(stderr,"%s(%d)/%d -- global_time %u", syscall_to_str(syscall), syscall, state, trace->global_time);
			break;
		}

		}
	}
	fprintf(stderr,"\n", 0);
}

int compare_register_files(char* name1, struct user_regs_struct* reg1, char* name2, struct user_regs_struct* reg2, int print, int stop)
{
	int err = 0;
	if (reg1->eax != reg2->eax) {
		if (print) {
			fprintf(stderr, "eax registers do not match: %s: %lx and %s: %lx\n", name1, reg1->eax, name2, reg2->eax);
		}
		err |= 0x1;
	}

	if (reg1->ebx != reg2->ebx) {
		if (print) {
			fprintf(stderr, "ebx registers do not match: %s: %lx and %s: %lx\n", name1, reg1->ebx, name2, reg2->ebx);
		}
		err |= 0x2;
	}
	/* check arg2 */
	if (reg1->ecx != reg2->ecx) {
		if (print) {
			fprintf(stderr, "ecx registers do not match: %s: %lx and %s: %lx\n", name1, reg1->ecx, name2, reg2->ecx);
		}
		err |= 0x4;
	}
	/* check arg3 */
	if (reg1->edx != reg2->edx) {
		if (print) {
			fprintf(stderr, "edx registers do not match: %s: %lx and %s: %lx\n", name1, reg1->edx, name2, reg2->edx);
		}
		err |= 0x8;
	}
	/* check arg4 */
	if (reg1->esi != reg2->esi) {
		if (print) {
			fprintf(stderr, "esi registers do not match: %s: %lx and %s: %lx\n", name1, reg1->esi, name2, reg2->esi);
		}
		err |= 0x10;
	}
	/* check arg5 */
	if (reg1->edi != reg2->edi) {
		if (print) {
			fprintf(stderr, "edi registers do not match: %s: %lx and %s: %lx\n", name1, reg1->edi, name2, reg2->edi);
		}
		err |= 0x20;
	}
	/* check arg6 */
	if (reg1->ebp != reg2->ebp) {
		if (print) {
			fprintf(stderr, "ebp registers do not match: %s: %lx and %s: %lx\n", name1, reg1->ebp, name2, reg2->ebp);
		}
		err |= 0x40;
	}
	/* check eip */
	if (reg1->eip != reg2->eip) {
		if (print) {
			fprintf(stderr, "eip registers do not match: %s: %lx and %s: %lx\n", name1, reg1->eip, name2, reg2->eip);
		}
		err = 1;
	}

	/* check eflags */
	if (reg1->eflags != reg2->eflags) {
		if (print) {
			fprintf(stderr, "eflags registers do not match: %s: %lx and %s: %lx\n", name1, reg1->eflags, name2, reg2->eflags);
		}
		err |= 0x80;
	}

	if (stop != 0 && err != 0) {
		fprintf(stderr, "bailing out\n");
		print_process_mmap(stop);
		sys_exit();
	}

	return err;
}

uint64_t str2ull(const char* start, size_t max_size)
{
	int idx = 0;
	while (start[idx] == ' ') {
		idx += 1;
	}

	uint64_t val = 0;
	while (start[idx] != ' ' && idx <= max_size && start[idx] != '\n') {
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
	while (start[idx] != ' ' && idx <= max_size && start[idx] != '\n') {
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

void read_line(FILE* file, char *buf, int size, char *name)
{
	if (feof(file) || fgets(buf, size, file) == NULL) {
		printf("error reading line in file: %s  -- bailing out\n", name);
		printf("buf: %p  size: %d\n",buf,size);
		perror("");
		exit(-1);
	}
}

static FILE* open_mmap(pid_t tid)
{
	char path[64];
	FILE* file;
	fflush(stdout);
	bzero(path, 64);
	sprintf(path, "/proc/%d/maps", tid);
	if ((file = fopen(path, "r")) == NULL) {
		perror("error reading child memory maps\n");
	}
	return file;
}

void print_process_mmap(pid_t tid)
{
	FILE* file = open_mmap(tid);
	int c = getc(file);
	while (c != EOF) {
		putchar(c);
		c = getc(file);
	}

	if (fclose(file) == EOF) {
		perror("error closing mmap file\n");
	}

	sleep(10);
}

/**
 * prints a child process memory sections content, according to /proc/pid/maps
 */

void print_process_memory(pid_t child)
{
	int i;
	const ssize_t length = snprintf(NULL, 0, "%lu", child) + 1;
	char buf[length];
	snprintf(buf, length, "%lu", child);

	char maps_str[1024] = {0};
	strcpy(maps_str,"/proc/");
	strcat(maps_str,buf);
	strcat(maps_str,"/maps");

	FILE *maps_file = fopen(maps_str,"r");
	unsigned int start, end;
	char flags[32], filename[128];
	unsigned long file_offset, dev_major, dev_minor, inode;

	fprintf(stderr,"Printing memory for process %d:\n",child);
	while ( fscanf(maps_file,"%x-%x %31s %Lx %x:%x %Lu", &start, &end,flags, &file_offset, &dev_major, &dev_minor, &inode) != EOF ) {
		/* read the remainder of the line into filename (it may be empty)*/
		while ( (filename[0] = fgetc(maps_file)) != ' ');
		for (i = 0 ; (filename[i] = fgetc(maps_file)) != '\n' ; ++i);
		filename[i] = '\0';
		fprintf(stderr,"\n%x-%x from %s:\n", start, end, filename);
		const ssize_t length = end - start;
		char buffer[length];
		read_child_buffer(child,start,length,buffer);
		for (i = 0 ; i < length ; i += 4) {
			unsigned long dword = *((unsigned long *)(buffer + i));
			fprintf(stderr,"%x | %d %d %d %d | [%x]\n",dword, buffer[i] , buffer[i+1], buffer[i+2], buffer[i+3], start + i);
			//fprintf(stderr,"%x",dword);
		}
		rand();
	}
	fclose(maps_file);
}

/**
 * This function checks if the specified memory region (start - end) is
 * mapped in the child process.
 * @return 0: if the memory region is not mapped
 * 		   1: if the memory region is mapped
 */
int check_if_mapped(struct context *ctx, void *start, void *end)
{
	pid_t tid = ctx->child_tid;

	FILE* file = open_mmap(tid);
	char buf[256];
	char tmp[9];
	bzero(tmp, 9);

	while (fgets(buf, 256, file)) {
		memcpy(tmp, buf, 8);
		void *mmap_start = (void*) strtoul(tmp, NULL, 16);
		memcpy(tmp, buf + 9, 8);
		void *mmap_end = (void*) strtoul(tmp, NULL, 16);

		if (start >= mmap_start && end <= mmap_end) {
			sys_fclose(file);
			return 1;
		}
	}

	sys_fclose(file);
	return 0;
}

/**
 * @start_addr: start address of where code should be injected
 * @code_size : given in bytes - must be a multiple of 4!
 */
struct current_state_buffer* init_code_injection(pid_t pid, void* start_addr, int code_size)
{
	//check if code size is a multiple of 4
	assert(code_size % 4 == 0);

	struct current_state_buffer* buf = sys_malloc(sizeof(struct current_state_buffer));
	buf->pid = pid;

	//save the current state of the register file
	read_child_registers(pid, &(buf->regs));

	//save original instructions; assure word alignment
	long* tmp = (long*) ((unsigned long) start_addr & ~0x3);
	long* code_buffer = sys_malloc(code_size + (2 * sizeof(long)));

	int i = 0;
	while ((uintptr_t) tmp + i < (uintptr_t) start_addr + code_size) {
		//TODO: re-implemnt read_code
		//code_buffer[i] = read_child_code(pid, tmp + i);
		//	printf("read instruction: %lx\n",code_buffer[i]);
		i++;
	}

	buf->code_size = i * 4;
	buf->code_buffer = code_buffer;
	buf->start_addr = tmp;
	return buf;
}

void inject_code(struct current_state_buffer* buf, char* code)
{
	int i;
	long data;

	char tmp_code[buf->code_size]; //inject_patraceme(current_tid);
	//ptrace(PTRACE_SETOPTIONS, current_tid, 0, PTRACE_O_TRACEEXIT | PTRACE_O_TRACECLONE | PTRACE_O_TRACESYSGOOD);

	memset(tmp_code, 0, buf->code_size);
	unsigned long original_start = buf->regs.eip;
	//assure alignment
	int offset = original_start & 0x3;
	memcpy(tmp_code + offset, code, 4);

	for (i = 0; i < buf->code_size / 4; i++) {
		memcpy(&data, tmp_code + i * 4, sizeof(long));
		write_child_code(buf->pid, buf->start_addr + i, data);
	}

}

void restore_original_state(struct current_state_buffer* buf)
{
	//restoring the original state involves two steps:
	//1. restore register file (including eip)
	write_child_registers(buf->pid, &(buf->regs));

	//2. copy the original code back to the child
	int i;
	for (i = 0; i < buf->code_size / 4; i++) {
		write_child_code(buf->pid, buf->start_addr + i, buf->code_buffer[i]);
	}
}

void cleanup_code_injection(struct current_state_buffer* buf)
{
	sys_free((void**) &buf->code_buffer);
	sys_free((void**) &buf);
}

/*
 * Helper function to print out a child memory right after the execv call
 * should be called right after the fork, on both parent and child.
 */
void read_child_initial_memory_end_exit(pid_t pid, char * executable, char * argv) {
    if(pid == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execv(executable, argv);
    }
    else {
        wait(NULL);
        print_register_file_tid(pid);
        print_process_memory(pid);
	    kill(pid,SIGKILL);
    }
}
