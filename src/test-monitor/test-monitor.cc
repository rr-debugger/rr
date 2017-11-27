#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace std;

static void print_usage(FILE* out) {
  fputs("Usage:\n"
        "test-monitor <timeout-secs> <out-file> <command> [<args>...]\n"
        "Runs the command for up to <timeout-secs>. If the timeout expires,\n"
        "or a SIGURG signal is received, attaches gdb to the child to get a\n"
        "stack trace and dumps various other information to <out-file>\n"
        "then exits with error code 124. Otherwise exits with the child's\n"
        "exit code. Runs the child with\n"
        "RUNNING_UNDER_TEST_MONITOR=<pid-of-test-monitor>.\n",
        out);
}

static unsigned long timeout;

static siginfo_t received_siginfo;

static void sighandler(__attribute__((unused)) int sig, siginfo_t* si,
                       __attribute__((unused)) void* ctx) {
  received_siginfo = *si;
}

struct ProcessInfo {
  ProcessInfo() : is_traced(false) {}
  vector<pid_t> children;
  string name;
  bool is_traced;
};

struct ProcessMap {
public:
  explicit ProcessMap(FILE* out);
  unordered_map<pid_t, ProcessInfo> map;
};

ProcessMap::ProcessMap(FILE* out) {
  DIR* proc = opendir("/proc");
  if (!proc) {
    fprintf(out, "Couldn't read /proc");
    return;
  }
  while (true) {
    struct dirent* f = readdir(proc);
    if (!f) {
      break;
    }
    pid_t pid = atoi(f->d_name);
    if (pid) {
      char path[PATH_MAX];
      sprintf(path, "/proc/%d/status", pid);
      FILE* status = fopen(path, "r");
      if (status) {
        while (true) {
          char buf[1024 * 10];
          if (!fgets(buf, sizeof(buf), status)) {
            break;
          }
          ssize_t len = strlen(buf);
          if (len > 0 && buf[len - 1] == '\n') {
            buf[len - 1] = 0;
          }
          if (strncmp(buf, "Name:", 5) == 0) {
            char* s = buf + 5;
            while (*s == ' ' || *s == '\t') {
              ++s;
            }
            map[pid].name = string(s);
          }
          if (strncmp(buf, "PPid:", 5) == 0) {
            pid_t ppid = atoi(buf + 5);
            if (ppid) {
              map[ppid].children.push_back(pid);
            }
          }
          if (strncmp(buf, "TracerPid:", 10) == 0) {
            pid_t tracer_pid = atoi(buf + 10);
            if (tracer_pid) {
              map[pid].is_traced = true;
            }
            break;
          }
        }
        fclose(status);
      }
    }
  }
  closedir(proc);
}

static void dump_proc_for_process(pid_t child, const char* suffix, FILE* out) {
  char path[PATH_MAX];
  sprintf(path, "/proc/%d/%s", child, suffix);
  fprintf(out, "====== %s\n", path);
  FILE* f = fopen(path, "r");
  if (!f) {
    fprintf(out, "(file couldn't be opened)\n");
    return;
  }
  char line[1024 * 10];
  while (fgets(line, sizeof(line), f)) {
    fputs(line, out);
  }
  fclose(f);
}

static void dump_popen_cmdline(const char* cmdline, FILE* out) {
  fprintf(out, "====== %s\n", cmdline);
  FILE* st = popen(cmdline, "r");
  if (!st) {
    fprintf(out, "(execution failed)\n");
    return;
  }
  char line[1024 * 10];
  while (fgets(line, sizeof(line), st)) {
    fputs(line, out);
  }
  pclose(st);
}

static void dump_gdb_stacktrace(pid_t child, FILE* out) {
  char cmdline[1024 * 10];
  sprintf(cmdline, "gdb -p %d -ex 'set confirm off' -ex 'set height 0' -ex "
                   "'thread apply all bt' -ex q </dev/null 2>&1",
          child);
  dump_popen_cmdline(cmdline, out);
}

static void force_trace_closure(pid_t child, FILE* out) {
  char cmdline[1024 * 10];
  sprintf(cmdline, "gdb -p %d -ex 'set confirm off' -ex 'set height 0' -ex "
                   "'p rr::force_close_record_session()' -ex q </dev/null 2>&1",
          child);
  dump_popen_cmdline(cmdline, out);
}

static void dump_emergency_debugger(char* gdb_cmd, FILE* out) {
  char cmdline[1024 * 10];
  char* file_name = nullptr;
  for (ssize_t i = strlen(gdb_cmd) - 1; i >= 0; --i) {
    if (gdb_cmd[i] == ' ') {
      gdb_cmd[i] = 0;
      file_name = &gdb_cmd[i + 1];
      break;
    }
  }
  if (!file_name) {
    fprintf(out, "Can't find file name in cmd %s\n", gdb_cmd);
    return;
  }
  sprintf(cmdline, "%s -ex 'set confirm off' -ex 'set height 0' "
                   "-ex 'info registers' -ex "
                   "'thread apply all bt' -ex q %s </dev/null 2>&1",
          gdb_cmd, file_name);
  dump_popen_cmdline(cmdline, out);
}

static vector<pid_t> get_child_threads(pid_t pid) {
  vector<pid_t> ret;
  char path[PATH_MAX];
  sprintf(path, "/proc/%d/task", pid);
  DIR* threads = opendir(path);
  if (threads) {
    while (true) {
      struct dirent* t = readdir(threads);
      if (!t) {
        break;
      }
      pid_t tid = atoi(t->d_name);
      if (tid && tid != pid) {
        ret.push_back(tid);
      }
    }
    closedir(threads);
  }
  return ret;
}

/**
 * Dumps purely passive data for the entire process subtree.
 */
static void dump_subtree(ProcessMap& child_processes,
                         unordered_set<pid_t>& visited, pid_t child, FILE* out,
                         pid_t* rr_pid) {
  if (visited.find(child) != visited.end()) {
    fprintf(out, "Warning: tree structure violation detected at process %d\n",
            child);
    return;
  }
  visited.insert(child);

  dump_proc_for_process(child, "status", out);
  dump_proc_for_process(child, "stack", out);

  auto threads = get_child_threads(child);
  for (pid_t p : threads) {
    dump_proc_for_process(p, "status", out);
    dump_proc_for_process(p, "stack", out);
  }

  auto it = child_processes.map.find(child);
  if (it != child_processes.map.end()) {
    if (!*rr_pid && it->second.name == "rr") {
      *rr_pid = child;
    }
    for (pid_t p : it->second.children) {
      dump_subtree(child_processes, visited, p, out, rr_pid);
    }
  }
}

static void dump_state_and_kill(pid_t child, const char* out_file_name) {
  FILE* out = fopen(out_file_name, "a");
  if (!out) {
    fprintf(stderr, "Couldn't open %s for writing\n", out_file_name);
    return;
  }

  setlinebuf(out);

  if (received_siginfo.si_signo == SIGURG) {
    fprintf(out, "process %d sent SIGURG\n", received_siginfo.si_pid);
  } else {
    fprintf(out, "timeout %lu exceeded\n", timeout);
  }

  ProcessMap child_processes(out);
  unordered_set<pid_t> visited;
  pid_t rr_pid = 0;
  dump_subtree(child_processes, visited, child, out, &rr_pid);

  // We get a stacktrace for rr first. We don't try to get stacktraces for
  // all processes because sometimes attaching and then detaching gdb can
  // cause a process to wake up from a wait, and we don't want that. Attaching
  // and detaching from rr should be harmless.
  pid_t sig_pid =
      received_siginfo.si_signo == SIGURG ? received_siginfo.si_pid : 0;
  if (rr_pid || sig_pid) {
    if (rr_pid && sig_pid && rr_pid != sig_pid) {
      fprintf(out,
              "Confused about rr pid; signal says %d, process tree says %d\n",
              sig_pid, rr_pid);
    }
    dump_gdb_stacktrace(sig_pid ? sig_pid : rr_pid, out);

    if (sig_pid) {
      // Try to connect to the emergency debugger and get stack/regs.
      // If rr is in a broken state this might hang, so we do this last.
      FILE* gdb_cmd = fopen("gdb_cmd", "r");
      if (gdb_cmd) {
        char buf[1024 * 10];
        if (fgets(buf, sizeof(buf), gdb_cmd)) {
          dump_emergency_debugger(buf, out);
        }
        fclose(gdb_cmd);
      }
    } else {
      force_trace_closure(rr_pid, out);
    }
  }

  fclose(out);

  for (pid_t p : visited) {
    kill(p, SIGKILL);
  }
}

int main(int argc, char* argv[]) {
  if (argc < 4) {
    print_usage(stderr);
    return 1;
  }

  char* endp;
  timeout = strtoul(argv[1], &endp, 10);
  if (*endp || timeout > UINT32_MAX) {
    fprintf(stderr, "Invalid timeout %s\n", argv[1]);
    return 1;
  }

  pid_t child;
  while (true) {
    child = fork();
    if (child < 0) {
      if (errno == EAGAIN) {
        continue;
      }
      perror("fork failed");
      return 2;
    }
    if (child > 0) {
      break;
    }
    char buf[1024];
    sprintf(buf, "%d", getppid());
    setenv("RUNNING_UNDER_TEST_MONITOR", buf, 1);
    execvp(argv[3], &argv[3]);
    perror("exec failed");
    return 2;
  }

  struct sigaction sa;
  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = sighandler;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGURG, &sa, NULL);
  sigaction(SIGALRM, &sa, NULL);

  alarm(timeout);
  int status;
  int ret = waitpid(child, &status, 0);
  if (ret < 0) {
    if (errno != EINTR) {
      perror("waitpid failed");
      return 2;
    }
    if (!received_siginfo.si_signo) {
      fputs("Interrupted by unexpected signal\n", stderr);
      return 3;
    }

    dump_state_and_kill(child, argv[2]);
    abort();
  }
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  raise(WTERMSIG(status));
  return 3;
}
