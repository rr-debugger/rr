/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "DebuggerExtensionCommand.h"
#include "CheckpointInfo.h"

#include "ReplayTask.h"
#include "log.h"
#include <dirent.h>

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
  auto& timeline = *gdb_server.timeline();
  int checkpoint_id = ++gNextCheckpointId;
  const Checkpoint::Explicit e = timeline.can_add_checkpoint()
                                     ? Checkpoint::EXPLICIT
                                     : Checkpoint::NOT_EXPLICIT;
  gdb_server.checkpoints[checkpoint_id] =
      Checkpoint(timeline, gdb_server.last_continue_task, e, where);
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
  char* endptr;
  long id = strtol(args[0].c_str(), &endptr, 10);
  if (*endptr) {
    return string("Invalid checkpoint number ") + args[0] + ".";
  }
  auto it = gdb_server.checkpoints.find(id);
  if (it != gdb_server.checkpoints.end()) {
    if (it->second.is_explicit == Checkpoint::EXPLICIT) {
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

string invoke_load_checkpoint(GdbServer& server, Task*, const vector<string>&) {
  auto existing_checkpoints =
      server.current_session().as_replay()->get_persistent_checkpoints();
  auto cp_deserialized = 0;
  for (const auto& cp : existing_checkpoints) {
    if (server.persistent_checkpoint_is_loaded(cp.unique_id)) {
      LOG(debug) << "checkpoint at time " << cp.event_time()
                 << " already loaded";
      continue;
    }
    auto session = ReplaySession::create(
        server.current_session().as_replay()->trace_reader().dir(),
        server.timeline()->current_session().flags());
    int checkpoint_id = ++gNextCheckpointId;
    session->load_checkpoint(cp);

    server.checkpoints[checkpoint_id] =
        Checkpoint(*server.timeline(), cp, session);
    cp_deserialized++;
  }
  return "loaded " + std::to_string(cp_deserialized) + " checkpoints from disk";
}

// we only allow for 1 checkpoint at any particular event. This function
// returns true if it succeeded in creating a new directory, thus also
// signalling that there previously was no checkpoint with that name
static bool create_persistent_checkpoint_dir(const std::string& dir) {
  if (mkdir(dir.c_str(), 0755) == 0) {
    return true;
  }
  return false;
}

static SimpleDebuggerExtensionCommand load_checkpoint(
    "load-checkpoints", "loads persistent checkpoints", invoke_load_checkpoint);

string invoke_write_checkpoints(GdbServer& server, Task* t,
                                const vector<string>&) {
  auto checkpointsWritten = 0;
  const auto& trace_dir = t->session().as_replay()->trace_reader().dir();
  std::vector<CheckpointInfo> existing_checkpoints;

  for (auto& kvp : server.checkpoints) {
    auto& cp = kvp.second;
    if (cp.mark.has_rr_checkpoint()) {
      const auto checkpoint_dir =
          trace_dir + "/checkpoint-" + std::to_string(cp.mark.time());

      if (!cp.persistent() &&
          create_persistent_checkpoint_dir(checkpoint_dir)) {
        // if it's already made persistent don't serialize. if failure to create
        // directory, don't serialize
        CheckpointInfo info{ cp };
        if (info.serialize(*cp.mark.get_checkpoint())) {
          checkpointsWritten++;
          // update checkpoint to have the newly persisted cp's id.
          cp.unique_id = info.unique_id;
        }
      }
    } else {
      auto mark_with_clone =
          server.timeline()->find_closest_mark_with_clone(cp.mark);
      const auto checkpoint_dir =
          trace_dir + "/checkpoint-" + std::to_string(mark_with_clone->time());
      if (!mark_with_clone) {
        std::cout
            << "Could not find a session clone to serialize for checkpoint "
            << kvp.first << '\n';
      } else if (!cp.persistent() &&
                 create_persistent_checkpoint_dir(checkpoint_dir)) {
        // if it's already made persistent don't serialize. if failure to create
        // directory, don't serialize
        CheckpointInfo info{ cp, *mark_with_clone };
        if (info.serialize(*mark_with_clone->get_checkpoint())) {
          checkpointsWritten++;
          // update checkpoint to have the newly persisted cp's id.
          cp.unique_id = info.unique_id;
        }
      }
    }
  }

  return std::to_string(checkpointsWritten) +
         " new checkpoints serialized. (total: " +
         std::to_string(existing_checkpoints.size()) + ")";
}

static SimpleDebuggerExtensionCommand write_checkpoints(
    "write-checkpoints", "make checkpoints persist on disk.",
    invoke_write_checkpoints);

void DebuggerExtensionCommand::init_auto_args() {
  static __attribute__((unused)) int dummy = []() {
    checkpoint.add_auto_arg("rr-where");
    return 0;
  }();
}

} // namespace rr
