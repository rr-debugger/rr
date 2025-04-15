/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include <limits>

#include "Command.h"
#include "ExportImportCheckpoints.h"
#include "Flags.h"
#include "GdbServer.h"
#include "ReplaySession.h"
#include "ScopedFd.h"
#include "TraceField.h"
#include "core.h"
#include "kernel_metadata.h"
#include "log.h"
#include "main.h"

using namespace std;

namespace rr {

/**
 * 'rerun' is intended to be a more powerful form of 'rr replay -a'. It does
 * a replay without debugging support, but it provides options for tracing and
 * dumping tracee state. Initially it supports singlestepping through a range
 * of trace events, dumping selected register values after each step.
 */
class RerunCommand : public Command {
public:
  virtual int run(vector<string>& args) override;

protected:
  RerunCommand(const char* name, const char* help) : Command(name, help) {}
  // command_for_checkpoint is an in and out parameter.
  int run_internal(CommandForCheckpoint& command_for_checkpoint);

  static RerunCommand singleton;
};

RerunCommand RerunCommand::singleton(
    "rerun",
    " rr rerun [OPTION]... [<trace-dir>]\n"
    "  -e, --trace-end=<EVENT>    end tracing at <EVENT>\n"
    "  -f, --function=<ADDR>      when starting tracing, push sentinel return\n"
    "                             address and jump to <ADDR> to fake call\n"
    "  --singlestep=<REGS>        dump <REGS> after each singlestep\n"
    "  --event-regs=<REGS>        dump <REGS> after each event\n"
    "  --export-checkpoints=<EVENT>,<NUM>,<FILE>\n"
    "                             Run to start of <EVENT> and then export checkpoints over\n"
    "                             Unix socket at <FILE>. Exit after <NUM>\n"
    "                             connections to the socket.\n"
    "  --import-checkpoint=<FILE> Start the replay by importing a checkpoint from\n"
    "                             another rr instance exporting checkpoints at\n"
    "                             <FILE>\n"
    "  -r, --raw                  dump registers in raw format\n"
    "  -s, --trace-start=<EVENT>  start tracing at <EVENT>\n"
    "  -u, --cpu-unbound          allow replay to run on any CPU. Default is\n"
    "                             to run on the CPU stored in the trace.\n"
    "                             Note that this may diverge from the recording\n"
    "                             in some cases.\n"
    "\n"
    "<REGS> is a comma-separated sequence of 'event','icount','ip','ticks',\n"
    "'flags','gp_x16','xmm_x16','ymm_x16'. For the 'x16' cases, we always output\n"
    "16 values, the latter 8 of which are zero for x86-32. GP registers are in\n"
    "architectural order (AX,CX,DX,BX,SP,BP,SI,DI,R8-R15). All data is output\n"
    "in little-endian binary format; records are separated by \\n. String\n"
    "instruction repetitions are treated as a single instruction if not\n"
    "interrupted. A 'singlestep' includes events such as system-call-exit\n"
    "where tracee state changes without any user-level instructions actually\n"
    "being executed.\n");

struct RerunFlags {
  FrameTime trace_start;
  FrameTime trace_end;
  remote_code_ptr function;
  vector<TraceField> singlestep_trace;
  vector<TraceField> event_trace;
  string import_checkpoint_socket;
  string export_checkpoints_socket;
  FrameTime export_checkpoints_event;
  int export_checkpoints_count;
  bool raw;
  bool cpu_unbound;

  RerunFlags()
      : trace_start(0),
        trace_end(numeric_limits<decltype(trace_end)>::max()),
        export_checkpoints_event(0),
        export_checkpoints_count(0),
        raw(false),
        cpu_unbound(false) {}
};

static bool parse_rerun_arg(vector<string>& args, RerunFlags& flags) {
  if (parse_global_option(args)) {
    return true;
  }

  static const OptionSpec options[] = {
    { 1, "singlestep", HAS_PARAMETER },
    { 2, "event-regs", HAS_PARAMETER },
    { 3, "export-checkpoints", HAS_PARAMETER },
    { 4, "import-checkpoint", HAS_PARAMETER },
    { 'e', "trace-end", HAS_PARAMETER },
    { 'f', "function", HAS_PARAMETER },
    { 'r', "raw", NO_PARAMETER },
    { 's', "trace-start", HAS_PARAMETER },
    { 'u', "cpu-unbound", NO_PARAMETER }
  };
  ParsedOption opt;
  if (!Command::parse_option(args, options, &opt)) {
    return false;
  }

  switch (opt.short_name) {
    case 1:
      if (!parse_trace_fields(opt.value, &flags.singlestep_trace)) {
        return false;
      }
      break;
    case 2:
      if (!parse_trace_fields(opt.value, &flags.event_trace)) {
        return false;
      }
      break;
    case 3:
      if (!parse_export_checkpoints(opt.value, flags.export_checkpoints_event, flags.export_checkpoints_count, flags.export_checkpoints_socket)) {
        return false;
      }
      break;
    case 4:
      flags.import_checkpoint_socket = opt.value;
      break;
    case 'e':
      if (!opt.verify_valid_int(1, UINT32_MAX)) {
        return false;
      }
      flags.trace_end = opt.int_value;
      break;
    case 'f': {
      char* endptr;
      flags.function = strtoul(opt.value.c_str(), &endptr, 0);
      if (*endptr) {
        fprintf(stderr, "Invalid function address %s\n", opt.value.c_str());
        return false;
      }
      break;
    }
    case 'r':
      flags.raw = true;
      break;
    case 's':
      if (!opt.verify_valid_int(1, UINT32_MAX)) {
        return false;
      }
      flags.trace_start = opt.int_value;
      break;
    case 'u':
      flags.cpu_unbound = true;
      break;
    default:
      DEBUG_ASSERT(0 && "Unknown option");
  }
  return true;
}

static bool treat_event_completion_as_singlestep_complete(const Event& ev) {
  switch (ev.type()) {
    case EV_PATCH_SYSCALL:
      return !ev.PatchSyscall().patch_vsyscall;
    case EV_INSTRUCTION_TRAP:
    case EV_SYSCALL:
      return true;
    default:
      return false;
  }
}

/**
 * Return true if the final "event" state change doesn't really change any
 * user-visible state and is therefore not to be considered a singlestep for
 * our purposes.
 */
static bool ignore_singlestep_for_event(const Event& ev) {
  switch (ev.type()) {
    // These don't actually change user-visible state, so we skip them.
    case EV_SIGNAL:
    case EV_SIGNAL_DELIVERY:
      return true;
    default:
      return false;
  }
}

static const uint64_t sentinel_ret_address = 9;

static void run_diversion_function(ReplaySession& replay, Task* task,
                                   const RerunFlags& flags) {
  DiversionSession::shr_ptr diversion_session = replay.clone_diversion();
  ReplayTask* t = diversion_session->find_task(task->tuid())->as_replay();
  Registers regs = t->regs();
  // align stack
  auto sp = remote_ptr<uint64_t>(regs.sp().as_int() & ~uintptr_t(0xf)) - 1;
  t->write_mem(sp.cast<uint64_t>(), sentinel_ret_address);
  regs.set_sp(sp);
  regs.set_ip(flags.function);
  regs.set_di(0);
  regs.set_si(0);
  t->set_regs(regs);
  RunCommand cmd =
      flags.singlestep_trace.empty() ? RUN_CONTINUE : RUN_SINGLESTEP;

  while (true) {
    DiversionSession::DiversionResult result =
        diversion_session->diversion_step(t, cmd);
    print_trace_fields(t, 0, 0, flags.raw, flags.singlestep_trace, stdout);
    if (result.break_status.signal) {
      if (result.break_status.signal->si_signo == SIGSEGV &&
          result.break_status.signal->si_addr == (void*)sentinel_ret_address) {
        return;
      }
      ASSERT(task, false) << "Unexpected signal "
                          << *result.break_status.signal;
    }

    if (result.status == DiversionSession::DiversionStatus::DIVERSION_EXITED) {
        LOG(debug) << "DIVERSION_EXITED, breaking out of diversion_step() loop";
        break;
    }
  }
}

static ReplaySession::Flags session_flags(const RerunFlags& flags) {
  ReplaySession::Flags result;
  result.redirect_stdio = false;
  result.share_private_mappings = false;
  result.cpu_unbound = flags.cpu_unbound;
  return result;
}

static int rerun(const string& trace_dir, const RerunFlags& flags, CommandForCheckpoint& command_for_checkpoint) {
  ScopedFd export_checkpoints_socket;
  // Construct the listening socket immediately so importers can connect early and block without polling.
  // If we need to import a checkpoint, we pass the socket in command_for_checkpoint.fds to the checkpoint
  // exporter's child process.
  if (flags.export_checkpoints_event) {
    if (command_for_checkpoint.session) {
      export_checkpoints_socket = std::move(command_for_checkpoint.fds.front());
    } else {
      export_checkpoints_socket = bind_export_checkpoints_socket(flags.export_checkpoints_count, flags.export_checkpoints_socket);
    }
  }

  ReplaySession::shr_ptr replay_session;
  if (command_for_checkpoint.session) {
    replay_session = std::move(command_for_checkpoint.session);
  } else if (flags.import_checkpoint_socket.empty()) {
    replay_session = ReplaySession::create(trace_dir, session_flags(flags));
    // Now that we've spawned the replay, raise our resource limits if
    // possible.
    raise_resource_limits();
  } else {
    vector<ScopedFd> fds;
    if (export_checkpoints_socket.is_open()) {
      fds.push_back(std::move(export_checkpoints_socket));
    }
    return invoke_checkpoint_command(flags.import_checkpoint_socket, command_for_checkpoint.args, std::move(fds));
  }

  uint64_t instruction_count_within_event = 0;
  bool done_first_step = false;
  bool need_to_singlestep = !flags.singlestep_trace.empty();
  for (auto& v : flags.event_trace) {
    if (v.kind == TRACE_INSTRUCTION_COUNT) {
      need_to_singlestep = true;
    }
  }

  while (replay_session->trace_reader().time() < flags.trace_end) {
    RunCommand cmd = RUN_CONTINUE;

    auto old_task_p = replay_session->current_task();
    ReplayTask* old_task = old_task_p ? old_task_p->as_replay() : nullptr;
    auto old_task_tuid = old_task ? old_task->tuid() : TaskUid();
    remote_code_ptr old_ip = old_task ? old_task->ip() : remote_code_ptr();
    FrameTime before_time = replay_session->trace_reader().time();
    if (replay_session->done_initial_exec() &&
        before_time >= flags.trace_start) {
      if (!done_first_step) {
        if (!flags.function.is_null()) {
          run_diversion_function(*replay_session, old_task, flags);
          return 0;
        }

        done_first_step = true;
        print_trace_fields(old_task, before_time - 1, instruction_count_within_event,
                           flags.raw, flags.singlestep_trace, stdout);
      }

      if (need_to_singlestep) {
        cmd = RUN_SINGLESTEP_FAST_FORWARD;
      }
    }

    Event replayed_event = replay_session->current_trace_frame().event();

    auto result = replay_session->replay_step(cmd);
    if (result.status == REPLAY_EXITED) {
      break;
    }

    FrameTime after_time = replay_session->trace_reader().time();
    if (cmd != RUN_CONTINUE) {
      // The old_task may have exited (and been deallocated) in the `replay_session->replay_step(cmd)` above.
      // So we need to try and obtain it from the session again to make sure it still exists.
      Task* old_task_p = old_task_tuid.tid() ? replay_session->find_task(old_task_tuid) : nullptr;
      ReplayTask* old_task = old_task_p ? old_task_p->as_replay() : nullptr;
      remote_code_ptr after_ip = old_task ? old_task->ip() : remote_code_ptr();
      DEBUG_ASSERT(after_time >= before_time && after_time <= before_time + 1);

      DEBUG_ASSERT(result.status == REPLAY_CONTINUE);
      DEBUG_ASSERT(result.break_status.watchpoints_hit.empty());
      DEBUG_ASSERT(!result.break_status.breakpoint_hit);
      DEBUG_ASSERT(cmd == RUN_SINGLESTEP_FAST_FORWARD ||
                   !result.break_status.singlestep_complete);

      // Treat singlesteps that partially executed a string instruction (that
      // was not interrupted) as not really singlestepping.
      bool singlestep_really_complete =
          result.break_status.singlestep_complete &&
          // ignore_singlestep_for_event only matters if we really completed the
          // event
          (!ignore_singlestep_for_event(replayed_event) ||
           before_time == after_time) &&
          (!result.incomplete_fast_forward || old_ip != after_ip ||
           before_time < after_time);
      if (cmd == RUN_SINGLESTEP_FAST_FORWARD &&
          (singlestep_really_complete ||
           (before_time < after_time &&
            treat_event_completion_as_singlestep_complete(replayed_event)))) {
        print_trace_fields(old_task, before_time, instruction_count_within_event,
                           flags.raw, flags.singlestep_trace, stdout);
      }

      if (singlestep_really_complete) {
        instruction_count_within_event += 1;
      }
    }
    if (before_time < after_time) {
      LOG(debug) << "Completed event " << before_time
                 << " instruction_count=" << instruction_count_within_event;
      print_trace_fields(old_task, before_time, instruction_count_within_event,
                         flags.raw, flags.event_trace, stdout);
      instruction_count_within_event = 1;
    }

    if (after_time == flags.export_checkpoints_event) {
      command_for_checkpoint = export_checkpoints(std::move(replay_session),
          flags.export_checkpoints_count,
          export_checkpoints_socket, flags.export_checkpoints_socket);
      return 0;
    }
  }

  LOG(info) << "Rerun successfully finished";
  return 0;
}

int RerunCommand::run_internal(CommandForCheckpoint& command_for_checkpoint) {
  // parse args first
  bool found_dir = false;
  string trace_dir;
  RerunFlags flags;
  vector<string> args = command_for_checkpoint.args;

  while (!args.empty()) {
    if (parse_rerun_arg(args, flags)) {
      continue;
    }
    if (!found_dir && parse_optional_trace_dir(args, &trace_dir)) {
      found_dir = true;
      continue;
    }
    print_help(stderr);
    return 1;
  }

  assert_prerequisites();

  if (running_under_rr()) {
    if (!Flags::get().suppress_environment_warnings) {
      fprintf(stderr, "rr: rr pid %d running under parent %d. Good luck.\n",
              getpid(), getppid());
    }
    if (trace_dir.empty()) {
      fprintf(stderr,
              "rr: No trace-dir supplied. You'll try to rerun the "
              "recording of this rr and have a bad time. Bailing out.\n");
      return 3;
    }
  }

  return rerun(trace_dir, flags, command_for_checkpoint);
}

int RerunCommand::run(vector<string>& args) {
  CommandForCheckpoint command_for_checkpoint;
  command_for_checkpoint.args = std::move(args);
  while (true) {
    ScopedFd exit_notification_fd = std::move(command_for_checkpoint.exit_notification_fd);
    int ret = run_internal(command_for_checkpoint);
    if (!command_for_checkpoint.session) {
      if (exit_notification_fd.is_open()) {
        notify_normal_exit(exit_notification_fd);
      }
      return ret;
    }
  }
}

} // namespace rr
