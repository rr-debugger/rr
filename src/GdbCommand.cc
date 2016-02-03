/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "GdbCommand"

#include "GdbCommand.h"

template <>
bool cast(const std::string& s, std::string& out_target,
          std::string& error_msg) {
  out_target = s;
  return true;
}

RR_CMD(CmdWhen, "when") {
  return std::string() + "Current event: " +
         std::to_string(t->current_trace_frame().time()) + "\n";
}

RR_CMD(CmdWhenTicks, "when-ticks") {
  return std::string() + "Current tick: " + std::to_string(t->tick_count()) +
         "\n";
}

RR_CMD(CmdWhenTid, "when-tid") {
  return std::string() + "Current tid: " + std::to_string(t->tid) + "\n";
}

static int gNextCheckpointId = 0;

RR_CMD_AUTO(CmdCheckpoint, "checkpoint", std::string where) {
  int checkpoint_id = ++gNextCheckpointId;
  if (gdb_server.timeline.can_add_checkpoint()) {
    gdb_server.checkpoints[checkpoint_id] = GdbServer::Checkpoint(
        gdb_server.timeline, gdb_server.last_continue_tuid,
        GdbServer::Checkpoint::EXPLICIT, where);
    return std::string() + "Checkpoint " + std::to_string(checkpoint_id) +
           " at " + where + "\n";
  } else {
    // TODO Use non-explicit mark checkpoints.
    return "Error: Checkpoints are not supported here.\n";
  }
}

RR_CMD_AUTO(CmdDeleteCheckpoint, "delete checkpoint", int id) {
  auto it = gdb_server.checkpoints.find(id);
  if (it != gdb_server.checkpoints.end()) {
    gdb_server.timeline.remove_explicit_checkpoint(it->second.mark);
    gdb_server.checkpoints.erase(it);
    return std::string() + "Deleted checkpoint " + std::to_string(id) + ".\n";
  } else {
    return std::string() + "No checkpoint number " + std::to_string(id) + ".\n";
  }
}

RR_CMD(CmdInfoCheckpoint, "info checkpoint") {
  if (gdb_server.checkpoints.size() == 0) {
    return "No checkpoints.\n";
  }
  std::string out = "ID\tWhen\tWhere\n";
  for (auto& c : gdb_server.checkpoints) {
    out += std::to_string(c.first) + "\t" +
           std::to_string(c.second.mark.time()) + "\t" + c.second.where + "\n";
  }
  return out;
}

/*static*/ void GdbCommand::init_auto_args() {
  // TODO This would be nicer in the static block near the command definition.
  GdbCommandHandler::command_for_name("checkpoint")->add_auto_args("rr-where");
}
