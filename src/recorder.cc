/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "Recorder"

#include "recorder.h"

#include <assert.h>
#include <linux/futex.h>
#include <linux/net.h>
#include <poll.h>
#include <sched.h>
#include <string.h>
#include <sys/epoll.h>
#include <sysexits.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include <sstream>
#include <string>

#include "preload/syscall_buffer.h"

#include "Flags.h"
#include "kernel_abi.h"
#include "kernel_supplement.h"
#include "log.h"
#include "PerfCounters.h"
#include "RecordSession.h"
#include "StringVectorToCharArray.h"
#include "task.h"
#include "TraceStream.h"
#include "util.h"

using namespace rr;
using namespace std;

/**
 * Create a pulseaudio client config file with shm disabled.  That may
 * be the cause of a mysterious divergence.  Return an envpair to set
 * in the tracee environment.
 */
static string create_pulseaudio_config() {
  // TODO let PULSE_CLIENTCONFIG env var take precedence.
  static const char pulseaudio_config_path[] = "/etc/pulse/client.conf";
  if (access(pulseaudio_config_path, R_OK)) {
    // Assume pulseaudio isn't installed
    return "";
  }
  char tmp[] = "/tmp/rr-pulseaudio-client-conf-XXXXXX";
  int fd = mkstemp(tmp);
  fcntl(fd, F_SETFD, FD_CLOEXEC);
  unlink(tmp);
  // The fd is deliberately leaked so that the /proc/fd link below works
  // indefinitely. But we stop it leaking into tracee processes.

  stringstream procfile;
  procfile << "/proc/" << getpid() << "/fd/" << fd;
  stringstream cmd;
  cmd << "cp " << pulseaudio_config_path << " " << procfile.str();

  int status = system(cmd.str().c_str());
  if (-1 == status || !WIFEXITED(status) || 0 != WEXITSTATUS(status)) {
    FATAL() << "The command '" << cmd.str() << "' failed.";
  }
  if (-1 == lseek(fd, 0, SEEK_END)) {
    FATAL() << "Failed to seek to end of file.";
  }
  char disable_shm[] = "disable-shm = true\n";
  ssize_t nwritten = write(fd, disable_shm, sizeof(disable_shm) - 1);
  if (nwritten != sizeof(disable_shm) - 1) {
    FATAL() << "Failed to append '" << disable_shm << "' to " << procfile.str();
  }
  stringstream envpair;
  envpair << "PULSE_CLIENTCONFIG=" << procfile.str();
  return envpair.str();
}

/**
 * Ensure that when we exec the tracee image, the rrpreload lib will
 * be preloaded.  Even if the syscallbuf is disabled, we have to load
 * the preload lib for correctness.
 */
static void ensure_preload_lib_will_load(const char* rr_exe,
                                         const vector<string>& envp) {
  static const char cmd[] = "check-preload-lib";
  char* argv[] = { const_cast<char*>(rr_exe), const_cast<char*>(cmd), nullptr };
  vector<string> ep = envp;
  static const char magic_envpair[] = "_RR_CHECK_PRELOAD=1";
  ep.push_back(magic_envpair);

  pid_t child = fork();
  if (0 == child) {
    execvpe(rr_exe, argv, StringVectorToCharArray(ep).get());
    FATAL() << "Failed to exec " << rr_exe;
  }
  int status;
  pid_t ret = waitpid(child, &status, 0);
  if (ret != child) {
    FATAL() << "Failed to wait for " << rr_exe << " child";
  }
  if (!WIFEXITED(status) || 0 != WEXITSTATUS(status)) {
    fprintf(stderr, "\n"
                    "rr: error: Unable to preload the '%s' library.\n"
                    "\n",
            Flags::get().syscall_buffer_lib_path.c_str());
    exit(EX_CONFIG);
  }
}

static void terminate_recording(RecordSession& session, int status = 0) {
  session.terminate_recording();
  LOG(info) << "  exiting, goodbye.";
  exit(status);
}

static bool term_request;

/**
 * A terminating signal was received.  Set the |term_request| bit to
 * terminate the trace at the next convenient point.
 *
 * If there's already a term request pending, then assume rr is wedged
 * and abort().
 */
static void handle_termsig(int sig) {
  if (term_request) {
    FATAL() << "Received termsig while an earlier one was pending.  We're "
               "probably wedged.";
  }
  LOG(info) << "Received termsig " << signalname(sig)
            << ", requesting shutdown ...\n";
  term_request = true;
}

static void install_termsig_handlers(void) {
  int termsigs[] = { SIGINT, SIGTERM };
  for (size_t i = 0; i < array_length(termsigs); ++i) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_termsig;
    sigaction(termsigs[i], &sa, nullptr);
  }
}

/** If |term_request| is set, then terminate_recording(). */
static void maybe_process_term_request(RecordSession& session) {
  if (term_request) {
    terminate_recording(session);
  }
}

/**
 * Pick a CPU at random to bind to, unless --cpu-unbound has been given,
 * in which case we return -1.
 */
static int choose_cpu() {
  if (Flags::get().cpu_unbound) {
    return -1;
  }

  // Pin tracee tasks to logical CPU 0, both in
  // recording and replay.  Tracees can see which HW
  // thread they're running on by asking CPUID, and we
  // don't have a way to emulate it yet.  So if a tracee
  // happens to be scheduled on a different core in
  // recording than replay, it can diverge.  (And
  // indeed, has been observed to diverge in practice,
  // in glibc.)
  //
  // Note that we will pin both the tracee processes *and*
  // the tracer process.  This ends up being a tidy
  // performance win in certain circumstances,
  // presumably due to cheaper context switching and/or
  // better interaction with CPU frequency scaling.
  return random() % get_num_cpus();
}

int record(const char* rr_exe, int argc, char* argv[], char** envp) {
  LOG(info) << "Start recording...";

  vector<string> args;
  for (int i = 0; i < argc; ++i) {
    args.push_back(argv[i]);
  }
  vector<string> env;
  for (; *envp; ++envp) {
    env.push_back(*envp);
  }

  int bind_to_cpu = choose_cpu();

  char cwd[PATH_MAX] = "";
  getcwd(cwd, sizeof(cwd));

  // LD_PRELOAD the syscall interception lib
  if (!Flags::get().syscall_buffer_lib_path.empty()) {
    string ld_preload = "LD_PRELOAD=";
    // Our preload lib *must* come first
    ld_preload += Flags::get().syscall_buffer_lib_path;
    auto it = env.begin();
    for (; it != env.end(); ++it) {
      if (it->find("LD_PRELOAD=") != 0) {
        continue;
      }
      // Honor old preloads too.  This may cause
      // problems, but only in those libs, and
      // that's the user's problem.
      ld_preload += ":";
      ld_preload += it->substr(it->find("=") + 1);
      break;
    }
    if (it == env.end()) {
      env.push_back(ld_preload);
    } else {
      *it = ld_preload;
    }
  }

  string env_pair = create_pulseaudio_config();
  if (!env_pair.empty()) {
    env.push_back(env_pair);
  }

  ensure_preload_lib_will_load(rr_exe, env);

  install_termsig_handlers();

  auto session = RecordSession::create(args, env, cwd, bind_to_cpu);

  RecordSession::StepResult step_result;
  while ((step_result = session->record_step()).status ==
         RecordSession::STEP_CONTINUE) {
    maybe_process_term_request(*session);
  }

  if (step_result.status == RecordSession::STEP_EXEC_FAILED) {
    fprintf(stderr,
            "\n"
            "rr: error:\n"
            "  Unexpected `write()' call from first tracee process.\n"
            "  Most likely, the executable image `%s' is 64-bit, doesn't "
            "exist, or\n"
            "  isn't in your $PATH.  Terminating recording.\n"
            "\n",
            session->trace_writer().initial_exe().c_str());
    terminate_recording(*session);
  }

  if (step_result.status == RecordSession::STEP_PERF_COUNTERS_UNAVAILABLE) {
    fprintf(stderr, "\n"
                    "rr: internal recorder error:\n"
                    "  Performance counter doesn't seem to be working.  Are "
                    "you perhaps\n"
                    "  running rr in a VM but didn't enable perf-counter "
                    "virtualization?\n");
    terminate_recording(*session, EX_UNAVAILABLE);
  }

  assert(step_result.status == RecordSession::STEP_EXITED);
  LOG(info) << "Done recording -- cleaning up";
  return step_result.exit_code;
}
