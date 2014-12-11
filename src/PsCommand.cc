/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <map>

#include "Command.h"
#include "main.h"
#include "TraceStream.h"
#include "TraceTaskEvent.h"

using namespace std;

class PsCommand : public Command {
public:
  virtual int run(std::vector<std::string>& args);

protected:
  PsCommand(const char* name, const char* help) : Command(name, help) {}

  static PsCommand singleton;
};

PsCommand PsCommand::singleton("ps", " rr ps [<trace_dir>]\n");

static void print_exec_cmd_line(const TraceTaskEvent& event, FILE* out) {
  bool first = true;
  for (auto& word : event.cmd_line()) {
    fprintf(out, "%s%s", first ? "" : " ", word.c_str());
    first = false;
  }
  fprintf(out, "\n");
}

static void update_tid_to_pid_map(std::map<pid_t, pid_t>& tid_to_pid,
                                  const TraceTaskEvent& e) {
  if (e.type() == TraceTaskEvent::CLONE) {
    if (e.clone_flags() & CLONE_VM) {
      // thread clone. Record thread's pid.
      tid_to_pid[e.tid()] = tid_to_pid[e.parent_tid()];
    } else {
      // Some kind of fork. This task is its own pid.
      tid_to_pid[e.tid()] = e.tid();
    }
  }
}

static int ps(const string& trace_dir, FILE* out) {
  TraceReader trace(trace_dir);

  fprintf(out, "PID\tPPID\tCMD\n");

  vector<TraceTaskEvent> events;
  while (trace.good()) {
    events.push_back(trace.read_task_event());
  }

  if (events.empty() || events[0].type() != TraceTaskEvent::EXEC) {
    fprintf(stderr, "Invalid trace\n");
    return 1;
  }

  std::map<pid_t, pid_t> tid_to_pid;

  fprintf(out, "%d\t--\t", events[0].tid());
  print_exec_cmd_line(events[0], out);
  tid_to_pid[events[0].tid()] = events[0].tid();

  for (size_t i = 1; i < events.size(); ++i) {
    auto& e = events[i];
    update_tid_to_pid_map(tid_to_pid, e);

    if (e.type() == TraceTaskEvent::CLONE && !(e.clone_flags() & CLONE_VM)) {
      fprintf(out, "%d\t%d\t", e.tid(), tid_to_pid[e.parent_tid()]);

      // Look ahead for an EXEC in one of this process' threads.
      std::map<pid_t, pid_t> tmp_tid_to_pid = tid_to_pid;
      for (size_t j = i + 1; j < events.size(); ++j) {
        auto& ej = events[j];

        if (tmp_tid_to_pid[ej.tid()] == tmp_tid_to_pid[e.tid()] &&
            ej.type() == TraceTaskEvent::EXEC) {
          print_exec_cmd_line(events[j], out);
          break;
        }

        update_tid_to_pid_map(tmp_tid_to_pid, ej);

        if (ej.tid() == e.tid() && ej.type() == TraceTaskEvent::EXIT) {
          // The main thread exited. All other threads must too, so there
          // is no more opportunity for e's pid to exec.
          fprintf(out, "(forked without exec)\n");
          break;
        }
      }
    }
  }
  return 0;
}

int PsCommand::run(std::vector<std::string>& args) {
  while (parse_global_option(args)) {
  }

  string trace_dir;
  if (!parse_optional_trace_dir(args, &trace_dir)) {
    print_help(stderr);
    return 1;
  }

  return ps(trace_dir, stdout);
}
