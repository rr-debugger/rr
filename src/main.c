#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "share/dbg.h"
#include "share/hpc.h"
#include "share/sys.h"
#include "share/util.h"

#include "recorder/recorder.h"
#include "recorder/rec_sched.h"
#include "replayer/replayer.h"
#include "replayer/rep_sched.h"


static pid_t child;

#define MAX_ARGC_LEN	16
#define MAX_ENVC_LEN	128
#define MAX_ARGV_LEN	128
#define MAX_ENVP_LEN	1500
#define MAX_EXEC_LEN    128



static char** __argv;
static char** __envp;
static char* __executable;

static void alloc_argc(int argc)
{
	int i;
	assert(argc -1 < MAX_ARGC_LEN);
	__argv = sys_malloc(MAX_ARGC_LEN * sizeof(char*));

	for (i = 0; i < MAX_ARGC_LEN; i++) {
		__argv[i] = sys_malloc(MAX_ARGV_LEN);
	}

}

static void alloc_envp(char** envp)
{
	int i;

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
	int i = 0;
	while (envp[i] != NULL) {
		assert (i < MAX_ENVC_LEN);
		int arglen = strlen(envp[i]);
		assert(arglen < MAX_ENVP_LEN);
		strncpy(__envp[i], envp[i], arglen + 1);
		i++;
	}
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

void print_usage()
{
	printf("rr: missing/incorrect operands. usage is: rr --{record,replay} [--redirect_output] [--dump_on=<syscall|-signal>] [--dump_at=<time>] [--checksum={on-syscalls,on-all-events}|<from-time>] executable [args].\n");
}

static void install_signal_handler()
{
	signal(SIGINT, sig_child);
}

/**
 * main replayer method
 */
static void start(struct flags rr_flags, int argc, char* argv[], char** envp)
{
	pid_t pid;
	int status;

	if (rr_flags.option == RECORD) {
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
			open_trace_files(rr_flags);
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
			log_info("Start recording...\n");
			start_recording(rr_flags);
			log_info("Done recording -- cleaning up\n");
			/* cleanup all initialized data-structures */
			close_trace_files();
			close_libpfm();
		}

		/* replayer code comes here */
	} else if (rr_flags.option == REPLAY) {
		init_environment(argv[0], &argc, __argv, __envp);

		copy_executable(__argv[0]);
		if (access(__executable, X_OK)) {
			printf("The specified file '%s' does not exist or is not executable\n", __executable);
			return;
		}

		pid = sys_fork();

		//read_child_initial_memory_end_exit(pid,__executable,__argv);

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
			rep_sched_init();
			/* sets the file pointer to the first trace entry */

			rep_setup_trace_dir(argv[0]);
			open_trace_files(rr_flags);
			rep_init_trace_files();

			pid_t rec_main_thread = get_recorded_main_thread();
			rep_sched_register_thread(pid, rec_main_thread);

			/* main loop */
			replay(rr_flags);
			/* thread wants to exit*/
			close_libpfm();
			close_trace_files();
			rep_sched_close();
		}
	}
}

void check_prerequisites() {
	FILE *aslr_file = sys_fopen("/proc/sys/kernel/randomize_va_space","r");
	int aslr_val;
	fscanf(aslr_file,"%d",&aslr_val);
	if (aslr_val != 0)
		assert(0 && "ASLR not disabled, exiting.");
	sys_fclose(aslr_file);

	FILE *ptrace_scope_file = fopen("/proc/sys/kernel/yama/ptrace_scope","r");
	/* This file does not necessarily have to exist. */
	if (ptrace_scope_file != NULL) {
		int ptrace_scope_val;
		fscanf(ptrace_scope_file,"%d",&ptrace_scope_val);
		if (ptrace_scope_val != 0)
			assert(0 && "Can't write to process memory, exiting.");
		sys_fclose(ptrace_scope_file);
	}
}

/**
 * This is where recorder and the replayer start
 */
int main(int argc, char* argv[], char** envp)
{
	struct flags rr_flags = {0};
	rr_flags.dump_on = DUMP_ON_NONE;
	rr_flags.dump_at = DUMP_AT_NONE;
	rr_flags.checksum = CHECKSUM_NONE;

	/* check prerequisites for rr to run */
	check_prerequisites();

	/* check for sufficient amount of arguments */
	if (argc < 3) {
		print_usage();
		return 0;
	}

	int flag_index = 1;

	// mandatory {record,replay} flag
	if (flag_index < argc) {
		if (strncmp("--record", argv[flag_index], sizeof("--record")) == 0) {
			rr_flags.option = RECORD;
		} else if (strncmp("--replay", argv[flag_index], sizeof("--replay")) == 0) {
			rr_flags.option = REPLAY;
		}
		flag_index++;
	}

	if (rr_flags.option == INVALID) {
		print_usage();
		return 0;
	}


	// optional redirect flag
	if  (flag_index < argc && strncmp("--redirect_output", argv[flag_index], sizeof("--redirect_output")) == 0) {
		rr_flags.redirect = TRUE;
		flag_index++;
	}

	// optional dump memory on syscall flag
	if  (flag_index < argc && strncmp("--dump_on=", argv[flag_index], sizeof("--dump_on=") - 1) == 0) {
		sscanf(argv[flag_index],"--dump_on=%d",&rr_flags.dump_on);
		flag_index++;
	}

	// optional dump memory at global time flag
	if  (flag_index < argc && strncmp("--dump_at=", argv[flag_index], sizeof("--dump_at=") - 1) == 0) {
		sscanf(argv[flag_index],"--dump_at=%d",&rr_flags.dump_at);
		flag_index++;
	}

	// optional checksum memory
	if  (flag_index < argc && strncmp("--checksum=", argv[flag_index], sizeof("--checksum=") - 1) == 0) {
		char checksum_point[128];
		sscanf(argv[flag_index],"--checksum=%s",checksum_point);
		if (strncmp("on-syscalls", checksum_point, sizeof("on-syscalls") - 1) == 0) {
			rr_flags.checksum = CHECKSUM_SYSCALL;
		} else if (strncmp("on-all-events", checksum_point, sizeof("on-all-events") - 1) == 0) {
			rr_flags.checksum = CHECKSUM_ALL;
		} else {
			rr_flags.checksum = str2li(checksum_point,LI_COLUMN_SIZE);
		}
		flag_index++;
	}

	/* allocate memory for the arguments that are passed to the
	 * client application. This is the first thing that has to be
	 * done to ensure that the pointers that are passed to the client
	 * are the same in the recorder/replayer.*/
	alloc_argc(argc);
	alloc_envp(envp);
	alloc_executable();

	start(rr_flags, argc - flag_index , argv + flag_index, envp);

	return 0;

}

