/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <assert.h>
#include <getopt.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>

#include "share/config.h"
#include "share/dbg.h"
#include "share/hpc.h"
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
	if (rr_flags()->syscall_buffer_lib_path) {
		/* XXX not strictly safe */
		char ld_preload[2 * PATH_MAX] = "LD_PRELOAD=";
		/* our preload lib *must* come first */
		strcat(ld_preload, rr_flags()->syscall_buffer_lib_path);
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

	if (rr_flags()->option == RECORD) {
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
			open_trace_files();
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
			rec_sched_register_thread(0, pid, DEFAULT_COPY);

			/* perform the action recording */
			log_info("Start recording...");
			record();
			log_info("Done recording -- cleaning up");
			/* cleanup all initialized data-structures */
			close_trace_files();
			close_libpfm();
		}

		/* replayer code comes here */
	} else if (rr_flags()->option == REPLAY) {
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
			open_trace_files();
			rep_init_trace_files();

			pid_t rec_main_thread = get_recorded_main_thread();
			rep_sched_register_thread(pid, rec_main_thread);

			/* main loop */
			replay();
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

static void print_usage()
{
	fputs(
"Usage: rr [OPTION] (record|replay) [OPTION]... [ARG]...\n"
"\n"
"Common options\n"
"  -c, --checksum={on-syscalls,on-all-events}|FROM_TIME\n"
"                             compute and store (during recording) or\n"
"                             read and verify (during replay) checksums\n"
"                             of each of a tracee's memory mappings either\n"
"                             at the end of all syscalls (`on-syscalls'),\n"
"                             at all events (`on-all-events'), or \n"
"                             starting from a global timepoint FROM_TIME\n"
"  -d, --dump-on=<SYSCALL_NUM|-SIGNAL_NUM>\n"
"                             dump memory at SYSCALL or SIGNAL to the\n"
"                             file `[trace_dir]/[tid].[time]_{rec,rep}':\n"
"                             `_rec' for dumps during recording, `_rep'\n"
"                             for dumps during replay\n"
"  -t, --dump-at=TIME         dump memory at global timepoint TIME\n"
"  -v, --verbose              log messages that may not be urgently \n"
"                             critical to the user\n"
"  -w, --wait-secs=<NUM_SECS> wait NUM_SECS seconds just after startup,\n"
"                             before initiating recording or replaying\n"
"\n"
"Syntax for `record'\n"
" rr record [OPTION]... <exe> [exe-args]...\n"
"  -b, --force-syscall-buffer force the syscall buffer preload library\n"
"                             to be used, even if that's probably a bad\n"
"                             idea\n"
"  -c, --num-cpu-ticks=<NUM>  maximum number of 'CPU ticks' (currently \n"
"                             retired conditional branches) to allow a \n"
"                             task to run before interrupting it\n"
"  -e, --num-events=<NUM>     maximum number of events (syscall \n"
"                             enter/exit, signal, CPU interrupt, ...) \n"
"                             to allow a task before descheduling it\n"
"  -i, --ignore-signal=<SIG>  block <SIG> from being delivered to tracees.\n"
"                             Probably only useful for unit tests.\n"
"  -n, --no-syscall-buffer    disable the syscall buffer preload library\n"
"                             even if it would otherwise be used"
"\n"
"Syntax for `replay'\n"
" rr replay [OPTION]... <trace-dir>\n"
"  -a, --autopilot            replay without debugger server\n"
"  -p, --dbgport=PORT         bind the debugger server to PORT\n"
"  -q, --no-redirect-output   don't replay writes to stdout/stderr\n"
"\n"
"A command line like `rr (-h|--help|help)...' will print this message.\n"
, stderr);
}

static int parse_record_args(int cmdi, int argc, char** argv,
			     struct flags* flags)
{
	struct option opts[] = {
		{ "force-syscall-buffer", no_argument, NULL, 'b' },
		{ "ignore-signal", required_argument, NULL, 'i' },
		{ "num-cpu-ticks", required_argument, NULL, 'c' },
		{ "num-events", required_argument, NULL, 'e' },
		{ "no-syscall-buffer", no_argument, NULL, 'n' },
		{ 0 }
	};
	optind = cmdi + 1;
	while (1) {
		int i = 0;
		switch (getopt_long(argc, argv, "+c:be:i:n", opts, &i)) {
		case -1:
			return optind;
		case 'b':
			flags->use_syscall_buffer = TRUE;
			break;
		case 'c':
			flags->max_rbc = MAX(1, atoi(optarg));
			break;
		case 'e':
			flags->max_events = MAX(1, atoi(optarg));
			break;
		case 'i':
			flags->ignore_sig = MIN(_NSIG - 1,
						MAX(1, atoi(optarg)));
			break;
		case 'n':
			flags->use_syscall_buffer = FALSE;
			break;
		default:
			return -1;
		}
	}
}

static int parse_replay_args(int cmdi, int argc, char** argv,
			     struct flags* flags)
{
	struct option opts[] = {
		{ "autopilot", no_argument, NULL, 'a' },
		{ "dbgport", required_argument, NULL, 'p' },
		{ "no-redirect-output", no_argument, NULL, 'q' },
		{ 0 }
	};
	optind = cmdi + 1;
	while (1) {
		int i = 0;
		switch (getopt_long(argc, argv, "+ap:q", opts, &i)) {
		case -1:
			return optind;
		case 'a':
			flags->autopilot = TRUE;
			break;
		case 'p':
			flags->dbgport = atoi(optarg);
			break;
		case 'q':
			flags->redirect = FALSE;
			break;
		default:
			return -1;
		}
	}
}

static int parse_common_args(int argc, char** argv, struct flags* flags)
{
	struct option opts[] = {
		{ "checksum", required_argument, NULL, 'c' },
		{ "dump-at", required_argument, NULL, 't' },
		{ "dump-on", required_argument, NULL, 'd' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "wait-secs", required_argument, NULL, 'w' },
		{ 0 }
	};
	while (1) {
		int i = 0;
		switch (getopt_long(argc, argv, "+c:d:t:vw:", opts, &i)) {
		case -1:
			return optind;
		case 'c':
			if (!strcmp("on-syscalls", optarg)) {
				log_info("checksumming on syscall exit");
				flags->checksum = CHECKSUM_SYSCALL;
			} else if (!strcmp("on-all-events", optarg)) {
				log_info("checksumming on all events");
				flags->checksum = CHECKSUM_ALL;
			} else {
				flags->checksum = str2li(optarg,
							 LI_COLUMN_SIZE);
				log_info("checksumming on at event %d",
					 flags->checksum);
			}
			break;
		case 'd':
			flags->dump_on = atoi(optarg);
			break;
		case 'v':
			flags->verbose = 1;
			break;
		case 'w':
			flags->wait_secs = atoi(optarg);
			break;
		case 't':
			flags->dump_at = atoi(optarg);
			break;
		default:
			return -1;
		}
	}

}

static int parse_args(int argc, char** argv, struct flags* flags)
{
	const char* exe = argv[0];
	const char* cmd;
	int cmdi;

	memset(flags, 0, sizeof(*flags));
	flags->max_rbc = DEFAULT_MAX_RBC;
	flags->max_events = DEFAULT_MAX_EVENTS;
	flags->checksum = CHECKSUM_NONE;
	flags->dbgport = -1;
	flags->dump_at = DUMP_AT_NONE;
	flags->dump_on = DUMP_ON_NONE;
	flags->redirect = TRUE;
	flags->use_syscall_buffer = TRUE;

	if (0 > (cmdi = parse_common_args(argc, argv, flags))) {
		return -1;
	}
	if (0 == cmdi || cmdi >= argc) {
		fprintf(stderr, "%s: must specify a command\n", exe);
		return -1;
	}

	cmd = argv[cmdi];
	if (!strcmp("record", cmd)) {
		flags->option = RECORD;
		return parse_record_args(cmdi, argc, argv, flags);
	}
	if (!strcmp("replay", cmd)) {
		flags->option = REPLAY;
		return parse_replay_args(cmdi, argc, argv, flags);
	}
	if (!strcmp("help", cmd) || !strcmp("-h", cmd)
	    || !strcmp("--help", cmd)) {
		return -1;
	}
	fprintf(stderr, "%s: unknown command `%s`\n", exe, cmd);
	return -1;
}

/**
 * This is where recorder and the replayer start
 */
int main(int argc, char* argv[], char** envp)
{
	int argi;		/* index of first positional argument */
	int wait_secs;
	struct flags* flags = rr_flags_for_init();

	assert_prerequisites();

	if (0 > (argi = parse_args(argc, argv, flags)) || argc <= argi) {
		print_usage();
		return 1;
	}

	wait_secs = flags->wait_secs;
	if (wait_secs > 0) {
		struct timespec ts =  { .tv_sec = wait_secs, .tv_nsec = 0 };
		log_info("Waiting %d seconds before continuing ...",
			 wait_secs);
		if (nanosleep_nointr(&ts)) {
			fatal("Failed to wait requested duration");
		}
		log_info("... continuing.");
	}

	if (RECORD == flags->option) {
		log_info("Scheduler using max_events=%d, max_rbc=%d",
			 flags->max_events, flags->max_rbc);

		if (!flags->use_syscall_buffer) {
			log_info("Syscall buffer disabled by flag");
		} else {
			/* We rely on the distribution package or the
			 * user to set up the LD_LIBRARY_PATH properly
			 * so that we can LD_PRELOAD the bare library
			 * name.  Trying to do otherwise is possible,
			 * but annoying. */
			flags->syscall_buffer_lib_path = SYSCALLBUF_LIB_FILENAME;
		}
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
