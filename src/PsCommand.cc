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
    if (e.type() == TraceTaskEvent::CLONE) {
      if (e.clone_flags() & CLONE_VM) {
        // thread fork. Record thread's pid.
        tid_to_pid[e.tid()] = tid_to_pid[e.parent_tid()];
      } else {
        // Some kind of fork. Find the command line.
        tid_to_pid[e.tid()] = e.tid();
        fprintf(out, "%d\t%d\t", e.tid(), tid_to_pid[e.parent_tid()]);
        for (size_t j = i + 1; j < events.size(); ++j) {
          if (events[j].tid() == e.tid()) {
            if (events[j].type() == TraceTaskEvent::EXEC) {
              print_exec_cmd_line(events[j], out);
              break;
            } else if (events[j].type() == TraceTaskEvent::EXIT) {
              fprintf(out, "(forked without exec)\n");
              break;
            }
          }
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
