#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "share/sys.h"
#include "recorder/recorder.h"
#include "recorder/write_trace.h"
#include "replayer/replayer.h"
#include "replayer/read_trace.h"

static pid_t child;

#define MAX_ARGC_LEN	16
#define MAX_ENVC_LEN	64
#define MAX_ARGV_LEN	128
#define MAX_ENVP_LEN	1500
#define MAX_EXEC_LEN    64

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
	for (i = 0; i < MAX_ENVP_LEN; i++) {
		__envp[i] = sys_malloc(MAX_ENVP_LEN);
	}
}

static void copy_argv(int argc, char* argv[])
{
	int i;
	for (i = 0; i < argc - 2; i++) {
		int arglen = strlen(argv[i]);
		assert(arglen + 1 < MAX_ARGV_LEN);
		strncpy(__argv[i], argv[i + 2], arglen + 1);
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
	printf("got signal %d\n", sig);
	kill(child, SIGQUIT);
	kill(getpid(), SIGQUIT);
}

void print_usage()
{
	printf("Please specify either the '--record' or '--replay' option!\n");
}

static void install_signal_handler()
{
	signal(SIGINT, sig_child);
}

/**
 * main replayer method
 */
int replayer(int argc, char* argv[], char** envp)
{
	pid_t pid;
	int status, fake_argc;

	//check input
	if (argc < 2) {
		printf("Please specify a binary you want to record\n");
		return 0;
	}

	if (strncmp("--record", argv[1], 7) == 0) {
		//executable = argv[2];
		copy_executable(argv[2]);
		if (access(__executable, X_OK)) {
			printf("The specified file '%s' does not exist or is not executable\n", __executable);
			return 0;
		}

		/* create directory for trace files */
		setup_trace_dir(0);

		/* initialize trace files */
		open_trace_files();
		init_trace_files();
		copy_argv(argc, argv);
		copy_envp(envp);
		record_argv_envp(argc, __argv, __envp);
		close_trace_files();

		pid = sys_fork();
		/* child process */
		if (pid == 0) {
			sys_start_trace(__executable, __argv, __envp);
			/* parent process */
		} else {
			child = pid;

			/* make sure that the child process dies when the master process gets interrupted */
			install_signal_handler();

			/* sync with the child process */
			sys_waitpid(pid, &status);

			/* configure the child process to get a message upon a thread start, fork(), etc. */
			sys_ptrace_setup(pid);

			/* initialize stuff */
			init_libpfm();
			/* initialize the trace file here -- we need to record argc and envp */
			open_trace_files();

			/* register thread at the scheduler and start the HPC */
			rec_sched_register_thread(0, pid);

			/* perform the action recording */
			record_trace();

			printf("done recording -- cleaning up\n");
			//cleaning up stuff
			close_trace_files();
			close_libpfm();
		}

		return 0;

	} else if (strncmp("--replay", argv[1], 7) == 0) {
		init_environment(argv[2], &fake_argc, __argv, __envp);

		copy_executable(__argv[0]);
		if (access(__executable, X_OK)) {
			printf("The specified file '%s' does not exist or is not executable\n", __executable);
			return 0;
		}

		pid = sys_fork();
		//child process
		if (pid == 0) {
			sys_start_trace(__executable, __argv, __envp);
			/* parent process */
		} else {
			child = pid;
			/* make sure that the child process dies when the master process gets interrupted */
			install_signal_handler();

			sys_waitpid(pid, &status);

			/* initialize stuff */
			init_libpfm();
			init_rep_sched();
			sys_ptrace_setup(pid);
			/* sets the file pointer to the first trace entry */

			read_trace_init(argv[2]);

			pid_t rec_main_thread = get_recorded_main_thread();
			rep_sched_register_thread(pid, rec_main_thread);

			/* main loop */
			replay();

			/* thread wants to exit*/
			close_libpfm();
			read_trace_close();
			close_rep_sched();
		}
		return 0;

	} else {
		assert(1==0);
	}

}

int main(int argc, char* argv[], char** envp)
{
	alloc_argc(argc);
	alloc_envp(envp);
	alloc_executable();

	if (argc > 1) {
		replayer(argc, argv, envp);
	} else {
		print_usage();
	}
	return 0;
}

