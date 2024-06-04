/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "DebuggerExtensionCommand.h"

#include "ReplayTask.h"
#include "log.h"

using namespace std;

namespace rr {

static SimpleDebuggerExtensionCommand elapsed_time(
    "elapsed-time",
    "Print elapsed time (in seconds) since the start of the trace, in the"
    " 'record' timeline.",
    [](GdbServer&, Task* t, const vector<string>&) {
      if (!t->session().is_replaying()) {
        return DebuggerExtensionCommandHandler::cmd_end_diversion();
      }

      ReplayTask* replay_t = static_cast<ReplayTask*>(t);
      double elapsed_time = replay_t->current_trace_frame().monotonic_time() -
                            replay_t->session().get_trace_start_time();

      return string("Elapsed Time (s): ") + to_string(elapsed_time);
    });

static SimpleDebuggerExtensionCommand when(
    "when", "Print the number of the last completely replayed rr event.",
    [](GdbServer&, Task* t, const vector<string>&) {
      if (!t->session().is_replaying()) {
        return DebuggerExtensionCommandHandler::cmd_end_diversion();
      }
      // The current event has not been completely replayed, so
      // we report the number of the previuos event.
      return string("Completed event: ") +
             to_string(
                 static_cast<ReplayTask*>(t)->current_trace_frame().time() - 1);
    });

static SimpleDebuggerExtensionCommand when_ticks(
    "when-ticks", "Print the current rr tick count for the current thread.",
    [](GdbServer&, Task* t, const vector<string>&) {
      if (!t->session().is_replaying()) {
        return DebuggerExtensionCommandHandler::cmd_end_diversion();
      }
      return string("Current tick: ") + to_string(t->tick_count());
    });

static SimpleDebuggerExtensionCommand when_tid(
    "when-tid", "Print the real tid for the current thread.",
    [](GdbServer&, Task* t, const vector<string>&) {
      if (!t->session().is_replaying()) {
        return DebuggerExtensionCommandHandler::cmd_end_diversion();
      }
      return string("Current tid: ") + to_string(t->tid);
    });

static std::vector<ReplayTimeline::Mark> back_stack;
static ReplayTimeline::Mark current_history_cp;
static std::vector<ReplayTimeline::Mark> forward_stack;
static SimpleDebuggerExtensionCommand rr_history_push(
    "rr-history-push", "Push an entry into the rr history.",
    [](GdbServer& gdb_server, Task* t, const vector<string>&) {
      if (!gdb_server.timeline()) {
        return string("Command requires a full debugging session.");
      }
      if (!t->session().is_replaying()) {
        // Don't create new history state inside a diversion
        return string();
      }
      if (current_history_cp) {
        back_stack.push_back(current_history_cp);
      }
      current_history_cp = gdb_server.timeline()->mark();
      forward_stack.clear();
      return string();
    });
static SimpleDebuggerExtensionCommand back(
    "back", "Go back one entry in the rr history.",
    [](GdbServer& gdb_server, Task* t, const vector<string>&) {
      if (!gdb_server.timeline()) {
        return string("Command requires a full debugging session.");
      }
      if (!t->session().is_replaying()) {
        return DebuggerExtensionCommandHandler::cmd_end_diversion();
      }
      if (back_stack.size() == 0) {
        return string("Can't go back. No more history entries.");
      }
      forward_stack.push_back(current_history_cp);
      current_history_cp = back_stack.back();
      back_stack.pop_back();
      gdb_server.timeline()->seek_to_mark(current_history_cp);
      return string();
    });
static SimpleDebuggerExtensionCommand forward(
    "forward", "Go forward one entry in the rr history.",
    [](GdbServer& gdb_server, Task* t, const vector<string>&) {
      if (!gdb_server.timeline()) {
        return string("Command requires a full debugging session.");
      }
      if (!t->session().is_replaying()) {
        return DebuggerExtensionCommandHandler::cmd_end_diversion();
      }
      if (forward_stack.size() == 0) {
        return string("Can't go forward. No more history entries.");
      }
      back_stack.push_back(current_history_cp);
      current_history_cp = forward_stack.back();
      forward_stack.pop_back();
      gdb_server.timeline()->seek_to_mark(current_history_cp);
      return string();
    });

static int gNextCheckpointId = 0;

string invoke_checkpoint(GdbServer& gdb_server, Task*,
                         const vector<string>& args) {
  if (!gdb_server.timeline()) {
    return string("Command requires a full debugging session.");
  }
  const string& where = args[0];
  if (gdb_server.in_debuggee_end_state) {
    return string("The program is not being run.");
  }
  int checkpoint_id = ++gNextCheckpointId;
  GdbServer::Checkpoint::Explicit e;
  if (gdb_server.timeline()->can_add_checkpoint()) {
    e = GdbServer::Checkpoint::EXPLICIT;
  } else {
    e = GdbServer::Checkpoint::NOT_EXPLICIT;
  }
  gdb_server.checkpoints[checkpoint_id] = GdbServer::Checkpoint(
      *gdb_server.timeline(), gdb_server.last_continue_task, e, where);
  return string("Checkpoint ") + to_string(checkpoint_id) + " at " + where;
}
static SimpleDebuggerExtensionCommand checkpoint(
  "checkpoint",
  "create a checkpoint representing a point in the execution\n"
  "use the 'restart' command to return to the checkpoint",
  invoke_checkpoint);

string invoke_delete_checkpoint(GdbServer& gdb_server, Task*,
                                const vector<string>& args) {
  if (args.size() < 1) {
    return "'delete checkpoint' requires an argument";
  }
  if (!gdb_server.timeline()) {
    return string("Command requires a full debugging session.");
  }
  int id = stoi(args[0]);
  auto it = gdb_server.checkpoints.find(id);
  if (it != gdb_server.checkpoints.end()) {
    if (it->second.is_explicit == GdbServer::Checkpoint::EXPLICIT) {
      gdb_server.timeline()->remove_explicit_checkpoint(it->second.mark);
    }
    gdb_server.checkpoints.erase(it);
    return string("Deleted checkpoint ") + to_string(id) + ".";
  } else {
    return string("No checkpoint number ") + to_string(id) + ".";
  }
}
static SimpleDebuggerExtensionCommand delete_checkpoint(
  "delete checkpoint",
  "remove a checkpoint created with the 'checkpoint' command",
  invoke_delete_checkpoint);

string invoke_info_checkpoints(GdbServer& gdb_server, Task*,
                               const vector<string>&) {
  if (gdb_server.checkpoints.size() == 0) {
    return "No checkpoints.";
  }
  string out = "ID\tWhen\tWhere";
  for (auto& c : gdb_server.checkpoints) {
    out += string("\n") + to_string(c.first) + "\t" +
           to_string(c.second.mark.time()) + "\t" + c.second.where;
  }
  return out;
}
static SimpleDebuggerExtensionCommand info_checkpoints(
  "info checkpoints",
  "list all checkpoints created with the 'checkpoint' command",
  invoke_info_checkpoints);

/*static*/ void DebuggerExtensionCommand::init_auto_args() {
  checkpoint.add_auto_arg("rr-where");
}

} // namespace rr
