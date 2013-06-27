/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <assert.h>
#include <getopt.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>

#include "share/dbg.h"
#include "share/hpc.h"
#include "share/seccomp-bpf.h"
#include "share/sys.h"
#include "share/syscall_buffer.h"
#include "share/util.h"

#include "recorder/recorder.h"
#include "recorder/rec_sched.h"
#include "replayer/replayer.h"
#include "replayer/rep_sched.h"

static pid_t child;

#define MAX_ARGC_LEN	64
#define MAX_ENVC_LEN	128
#define MAX_ARGV_LEN	1024
#define MAX_ENVP_LEN	2048
#define MAX_EXEC_LEN    512



static char** __argv;
static char** __envp;
static char* __executable;
struct flags __rr_flags = {0};

static void alloc_argc(int argc)
{
	int i;
	assert(argc + 1 < MAX_ARGC_LEN);
	__argv = sys_malloc(MAX_ARGC_LEN * sizeof(char*));

	for (i = 0; i < MAX_ARGC_LEN; i++) {
		__argv[i] = sys_malloc(MAX_ARGV_LEN);
	}

}

static void alloc_envp(char** envp)
{
	int i;
#ifndef NDEBUG
	for (i = 1; envp[i - 1]; ++i);
	/* the loop above counts the null sentinel */
	assert(i < MAX_ENVC_LEN);
#endif
	__envp = sys_malloc(MAX_ENVC_LEN * sizeof(char*));
	for (i = 0; i < MAX_ENVC_LEN; i++) {
		__envp[i] = sys_malloc(MAX_ENVP_LEN);
	}
}

static void copy_argv(int argc, char* argv[])
{
	int i;
	for (i = 0; i < argc; i++) {
		int arglen = strlen(argv[i]);
		assert(arglen + 1 < MAX_ARGV_LEN);
		strncpy(__argv[i], argv[i], arglen + 1);
	}
	__argv[i] = NULL;
}

static void copy_envp(char** envp)
{
	int i = 0, preload_index = -1;
	while (envp[i] != NULL) {
		assert (i < MAX_ENVC_LEN);
		int arglen = strlen(envp[i]);
		assert(arglen < MAX_ENVP_LEN);
		strncpy(__envp[i], envp[i], arglen + 1);
		if (envp[i] == strstr(envp[i], "LD_PRELOAD"))
			preload_index = i;
		i++;
	}
	/* LD_PRELOAD the syscall interception lib */
	if (__rr_flags.syscall_buffer_lib_path) {
		/* XXX not strictly safe */
		char ld_preload[2 * PATH_MAX] = "LD_PRELOAD=";
		/* our preload lib *must* come first */
		strcat(ld_preload, __rr_flags.syscall_buffer_lib_path);
		if (preload_index >= 0) {
			const char* old_preload = NULL;
			old_preload = strchr(envp[preload_index], '=') + 1;
			assert(old_preload);
			/* honor old preloads too.  this may cause
			 * problems, but only in those libs, and
			 * that's the user's problem. */
			strcat(ld_preload, ":");
			/* append old value */
			strcat(ld_preload, old_preload);
		} else {
			/* or if this is a new key/value, "allocate"
			 * an index for it */
			preload_index = i++;
		}
		strcpy(__envp[preload_index], ld_preload);
	}
	assert (i < MAX_ENVC_LEN);
	__envp[i] = 0;
}

static void alloc_executable()
{
	__executable = sys_malloc(MAX_EXEC_LEN);
}

static void copy_executable(char* exec)
{
	assert (strlen(exec) < MAX_EXEC_LEN);
	strcpy(__executable, exec);
}

/**
 * used to stop child process when the parent process bails out
 */
static void sig_child(int sig)
{
	log_info("Got signal %d\n", sig);
	flush_trace_files();
	kill(child, SIGQUIT);
	kill(getpid(), SIGQUIT);
}

static void install_signal_handler()
{
	signal(SIGINT, sig_child);
}

/**
 * main replayer method
 */
static void start(int argc, char* argv[], char** envp)
{
	pid_t pid;
	int status;

	if (__rr_flags.option == RECORD) {
		copy_executable(argv[0]);
		if (access(__executable, X_OK)) {
			log_err("The specified file '%s' does not exist or is not executable\n", __executable);
			sys_exit();
		}

		copy_argv(argc, argv);
		copy_envp(envp);
		/* create directory for trace files */
		rec_setup_trace_dir(0);

		pid = sys_fork();

		if (pid == 0) { /* child process */
			sys_start_trace(__executable, __argv, __envp);
		} else { /* parent process */
			/* initialize trace files */
			open_trace_files(__rr_flags);
			rec_init_trace_files();
			record_argv_envp(argc, __argv, __envp);

			child = pid;

			/* make sure that the child process dies when the master process gets interrupted */
			install_signal_handler();

			/* sync with the child process */
			sys_waitpid(pid, &status);

			/* configure the child process to get a message upon a thread start, fork(), etc. */
			sys_ptrace_setup(pid);

			/* initialize stuff */
			init_libpfm();

			/* register thread at the scheduler and start the HPC */
			rec_sched_register_thread(0, pid);

			/* perform the action recording */
			log_info("Start recording...");
			start_recording(__rr_flags);
			log_info("Done recording -- cleaning up");
			/* cleanup all initialized data-structures */
			close_trace_files();
			close_libpfm();
		}

		/* replayer code comes here */
	} else if (__rr_flags.option == REPLAY) {
		init_environment(argv[0], &argc, __argv, __envp);

		copy_executable(__argv[0]);
		if (access(__executable, X_OK)) {
			printf("The specified file '%s' does not exist or is not executable\n", __executable);
			return;
		}

		pid = sys_fork();

		if (pid == 0) { /* child process */
			sys_start_trace(__executable, __argv, __envp);
		} else { /* parent process */
			child = pid;
			/* make sure that the child process dies when the master process gets interrupted */
			install_signal_handler();

			sys_waitpid(pid, &status);
			sys_ptrace_setup(pid);

			/* initialize stuff */
			init_libpfm();
			/* sets the file pointer to the first trace entry */

			rep_setup_trace_dir(argv[0]);
			open_trace_files(__rr_flags);
			rep_init_trace_files();

			pid_t rec_main_thread = get_recorded_main_thread();
			rep_sched_register_thread(pid, rec_main_thread);

			/* main loop */
			replay(__rr_flags);
			/* thread wants to exit*/
			close_libpfm();
			close_trace_files();
		}
	}
}

/**
 * Open |filename| and scan it as if it contains a single integer
 * value.  Return the integer on success, or -1 on failure.
 */
static int read_int_file(const char* filename)
{
	FILE* inf = fopen(filename, "r");
	int val;
	if (!inf) {
		return -1;
	}
	if (1 != fscanf(inf, "%d", &val)) {
		fatal("Failed to scan integer from %s", filename);
	}
	fclose(inf);
	return val;
}

static void assert_prerequisites() {
	int aslr_val =
		read_int_file("/proc/sys/kernel/randomize_va_space");
	int ptrace_scope_val =
		read_int_file("/proc/sys/kernel/yama/ptrace_scope");
	if (aslr_val != 0) {
		fatal("ASLR not disabled; randomize is %d", aslr_val);
	}
	if (ptrace_scope_val > 0) {
		fatal("Can't write to process memory; ptrace_scope is %d",
		      ptrace_scope_val);
	}
}

static int is_seccomp_bpf_available() {
	struct sock_filter noop[] = { ALLOW_PROCESS };
	struct sock_fprog prog = { .len = (unsigned short)ALEN(noop),
				   .filter = noop };
	/* NB: if the SET_NO_NEW_PRIVS succeeds, it will prevent us
	 * from doing things like recording setuid programs.  Bad
	 * thing? */
	return (0 == prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
		&& 0 == prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog));
}

static void print_usage()
{
	fputs(
"Usage: rr (record|replay) [OPTION]... [ARG]...\n"
"\n"
"Syntax for `record'\n"
" rr record [OPTION]... <exe> [exe-args]...\n"
"  -b, --force-syscall-buffer force the syscall buffer preload library\n"
"                             to be used, even if that's probably a bad\n"
"                             idea\n"
"  -n, --no-syscall-buffer    disable the syscall buffer preload library\n"
"                             even if it would otherwise be used"
"\n"
"Syntax for `replay'\n"
" rr replay [OPTION]... <trace-dir>\n"
"  -a, --autopilot            replay without debugger server\n"
"  -c, --checksum={on-syscalls,on-all-events}|FROM_TIME\n"
"                             verify checksums either on all syscalls, all\n"
"                             events, or starting from global timepoint\n"
"                             FROM_TIME\n"
"  -d, --dump-on=<SYSCALL_NUM|-SIGNAL_NUM>\n"
"                             dump memory at SYSCALL or SIGNAL during replay\n"
"  -p, --dbgport=PORT         bind the debugger server to PORT\n"
"  -q, --no-redirect-output   don't replay writes to stdout/stderr\n"

"  -t, --dump-at=TIME         dump memory at global timepoint TIME\n"
, stderr);
}

static int parse_record_args(int argc, char** argv, struct flags* flags)
{
	struct option opts[] = {
		{ "force-syscall-buffer", no_argument, NULL, 'b' },
		{ "no-syscall-buffer", no_argument, NULL, 'n' },
		{ 0 }
	};
	while (1) {
		int i = 0;
		switch (getopt_long(argc, argv, "bn", opts, &i)) {
		case -1:
			return 0;
		case 'b':
			flags->use_syscall_buffer = TRUE;
			break;
		case 'n':
			flags->use_syscall_buffer = FALSE;
			break;
		default:
			return -1;
		}
	}
}

static int parse_replay_args(int argc, char** argv, struct flags* flags)
{
	struct option opts[] = {
		{ "autopilot", no_argument, NULL, 'a' },
		{ "checksum", required_argument, NULL, 'c' },
		{ "dump-on", required_argument, NULL, 'd' },
		{ "dbgport", required_argument, NULL, 'p' },
		{ "no-redirect-output", no_argument, NULL, 'q' },
		{ "dump-at", required_argument, NULL, 't' },		
		{ 0 }
	};
	while (1) {
		int i = 0;
		switch (getopt_long(argc, argv, "ac:d:p:qt:", opts, &i)) {
		case -1:
			return 0;
		case 'a':
			flags->autopilot = TRUE;
			break;
		case 'c':
			if (!strcmp("on-syscalls", optarg)) {
				flags->checksum = CHECKSUM_SYSCALL;
			} else if (!strcmp("on-all-events", optarg)) {
				flags->checksum = CHECKSUM_ALL;
			} else {
				flags->checksum = str2li(optarg,
							 LI_COLUMN_SIZE);
			}
			break;
		case 'd':
			flags->dump_on = atoi(optarg);
			break;
		case 'p':
			flags->dbgport = atoi(optarg);
			break;
		case 'q':
			flags->redirect = FALSE;
			break;
		case 't':
			flags->dump_at = atoi(optarg);
			break;
		default:
			return -1;
		}
	}
}

static int parse_args(int argc, char** argv, struct flags* flags, int* argi)
{
	const char* cmd = argv[1];
	int i;

	memset(flags, 0, sizeof(*flags));
	flags->checksum = CHECKSUM_NONE;
	flags->dbgport = -1;
	flags->dump_at = DUMP_AT_NONE;
	flags->dump_on = DUMP_ON_NONE;
	flags->redirect = TRUE;
	/* TODO default to disabling the syscall buffer, because it's
	 * buggy and not well tested at the moment. */
	flags->use_syscall_buffer = FALSE;

	if (argc < 2) {
		fprintf(stderr, "%s: must specify a command\n", argv[0]);
		return -1;
	}
	if (!strcmp("-h", cmd) || !strcmp("--help", cmd)) {
		return -1;
	}

	if (!strcmp("record", cmd)) {
		flags->option = RECORD;
	} else if (!strcmp("replay", cmd)) {
		flags->option = REPLAY;
	} else {
		fprintf(stderr, "%s: unknown command `%s`\n", argv[0], cmd);
		return -1;
	}

	*argi = -1;
	for (i = 2; i < argc; ++i) {
		if ('-' != argv[i][0]) {
			*argi = i;
			break;
		}
	}
	if (-1 == *argi) {
		fprintf(stderr, "%s: no arguments for `%s`\n", argv[0], cmd);
		return -1;
	}

	if (RECORD == flags->option) {
		return parse_record_args(*argi, argv + 1, flags);
	} else if (REPLAY == flags->option) {
		return parse_replay_args(*argi, argv + 1, flags);
	} else {
		fatal("Not reached");
	}
}

/**
 * This is where recorder and the replayer start
 */
int main(int argc, char* argv[], char** envp)
{
	int argi;		/* index of first positional argument */

	assert_prerequisites();

	if (parse_args(argc, argv, &__rr_flags, &argi) || argc <= argi) {
		print_usage();
		return 1;
	}

	if (!__rr_flags.use_syscall_buffer) {
		log_info("Syscall buffer disabled by flag");
	} else if (!is_seccomp_bpf_available()) {
		log_warn("seccomp-bpf not available on this system; syscall buffer disabled");
	} else {
		/* We rely on the distribution package or the user to
		 * set up the LD_LIBRARY_PATH properly so that we can
		 * LD_PRELOAD the bare library name.  Trying to do
		 * otherwise is possible, but annoying. */
		__rr_flags.syscall_buffer_lib_path = SYSCALL_BUFFER_LIB_FILENAME;
	}

	/* allocate memory for the arguments that are passed to the
	 * client application. This is the first thing that has to be
	 * done to ensure that the pointers that are passed to the client
	 * are the same in the recorder/replayer.*/
	alloc_argc(argc);
	alloc_envp(envp);
	alloc_executable();

	start(argc - argi , argv + argi, envp);

	return 0;

}
