/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <assert.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/wait.h>
#include <unistd.h>

#include <limits>

#include "AutoRemoteSyscalls.h"
#include "Command.h"
#include "ExportImportCheckpoints.h"
#include "Flags.h"
#include "RemixModule.h"
#include "ReplaySession.h"
#include "ReplayTask.h"
#include "core.h"
#include "log.h"
#include "main.h"

using namespace std;

namespace rr {

class RemixCommand : public Command {
public:
  virtual int run(vector<string>& args);

protected:
  RemixCommand(const char* name, const char* help) : Command(name, help) {}
  int run_internal(CommandForCheckpoint& command_for_checkpoint);

  static RemixCommand singleton;
};

RemixCommand RemixCommand::singleton(
    "remix",
    " rr remix [OPTION]... <tool> [<trace-dir>]\n"
    "  -d, --debug=<EVENT-NUM>   auto-debug before EVENT-NUM\n"
    "  -c, --checkpoint          create a checkpoint and emit pid map at\n"
    "                            start\n"
    "  --export-checkpoints=<EVENT>,<NUM>,<FILE>\n"
    "                            Run to start of <EVENT> and then export checkpoints over\n"
    "                            Unix socket at <FILE>. Exit after <NUM>\n"
    "                            connections to the socket.\n"
    "  --import-checkpoint=<FILE> Start the replay by importing a checkpoint from\n"
    "                            another rr instance exporting checkpoints at\n"
    "                            <FILE>\n"
    " --force-emulate-amd        force AMD emulation on (on Intel)\n"
    " --force-emulate-no-lzcnt-tzcnt force pretending that LZCNT/TZCNT are not present\n"
    "                            on the machine the trace was recorded on\n"
    "  -g, --goto=<EVENT-NUM>    start remix before EVENT-NUM\n"
    "  -i, --init-cookie=<N>     pass N to remix_init\n"
    "  -q, --no-redirect-output  don't replay writes to stdout/stderr\n"
    "  -s, --stop=<EVENT-NUM>    stop remix before EVENT-NUM\n"
    "  -t, --singlestep=<EVENT-NUM>   singlestep up to EVENT-NUM\n"
    "  -w, --wait-on-exit        wait for a fatal signal instead of exiting\n");

struct RemixFlags {
  /* When true, echo tracee stdout/stderr writes to console. */
  bool redirect;
  intptr_t init_cookie;
  FrameTime goto_event;
  FrameTime stop_event;
  FrameTime debug_event;
  FrameTime singlestep_event;
  string import_checkpoint_socket;
  string export_checkpoints_socket;
  FrameTime export_checkpoints_event;
  int export_checkpoints_count;
  vector<string> tool_args;
  bool wait_on_close;
  bool checkpoint;
  RemixTestOptions test_options;

  RemixFlags()
      : redirect(true),
        init_cookie(-1),
        goto_event(0),
        stop_event(0),
        debug_event(0),
        singlestep_event(0),
        export_checkpoints_event(0),
        export_checkpoints_count(0),
        wait_on_close(false),
        checkpoint(false),
        test_options(DEFAULT_TEST_OPTIONS) {}
};

static bool parse_remix_arg(std::vector<std::string>& args, RemixFlags& flags) {
  if (parse_global_option(args)) {
    return true;
  }

  static const OptionSpec options[] = { { 'c', "checkpoint", NO_PARAMETER },
                                        { 'd', "debug", HAS_PARAMETER },
                                        { 'g', "goto", HAS_PARAMETER },
                                        { 'i', "init-cookie", HAS_PARAMETER },
                                        { 'q', "no-redirect-output",
                                          NO_PARAMETER },
                                        { 's', "stop", HAS_PARAMETER },
                                        { 't', "singlestep", HAS_PARAMETER },
                                        { 'w', "wait-on-exit", NO_PARAMETER },
                                        { 0, "force-emulate-amd", NO_PARAMETER },
                                        { 1, "force-emulate-no-lzcnt-tzcnt", NO_PARAMETER },
                                        { 2, "force-emulate-xsave-region-layout-difference", NO_PARAMETER },
                                        { 3, "export-checkpoints", HAS_PARAMETER },
                                        { 4, "import-checkpoint", HAS_PARAMETER }
  };
  ParsedOption opt;
  if (!Command::parse_option(args, options, &opt)) {
    return false;
  }

  switch (opt.short_name) {
    case 'c':
      flags.checkpoint = true;
      break;
    case 'd':
      if (!opt.verify_valid_int(1, UINT32_MAX)) {
        return false;
      }
      flags.debug_event = opt.int_value;
      break;
    case 'g':
      if (!opt.verify_valid_int(0, UINT32_MAX)) {
        return false;
      }
      flags.goto_event = opt.int_value;
      break;
    case 'i':
      if (!opt.verify_valid_int(INTPTR_MIN, INTPTR_MAX)) {
        return false;
      }
      flags.init_cookie = opt.int_value;
      break;
    case 'q':
      flags.redirect = false;
      break;
    case 's':
      if (!opt.verify_valid_int(1, UINT32_MAX)) {
        return false;
      }
      flags.stop_event = opt.int_value;
      break;
    case 't':
      if (!opt.verify_valid_int(1, UINT32_MAX)) {
        return false;
      }
      flags.singlestep_event = opt.int_value;
      break;
    case 'w':
      flags.wait_on_close = true;
      break;
    case 0:
      flags.test_options.force_emulate_amd = true;
      break;
    case 1:
      flags.test_options.force_emulate_no_lzcnt_tzcnt = true;
      break;
    case 2:
      flags.test_options.force_emulate_xsave_region_layout_difference = true;
      break;
    case 3:
      if (!parse_export_checkpoints(opt.value, flags.export_checkpoints_event,
                                    flags.export_checkpoints_count, flags.export_checkpoints_socket)) {
        return false;
      }
      break;
    case 4:
      flags.import_checkpoint_socket = opt.value;
      break;
    default:
      DEBUG_ASSERT(0 && "Unknown option");
  }
  return true;
}

static ReplaySession::Flags session_flags(const RemixFlags& flags, bool always_remix) {
  ReplaySession::Flags result;
  result.redirect_stdio = flags.redirect;
  result.cpu_unbound = always_remix;
  result.transient_errors_fatal = true;
  result.always_remix = always_remix;
  return result;
}

static string find_remix_module_path() {
  return resource_path() + "lib/rr/librrremix";
}

static ReplayResult auto_debug(ReplaySession::shr_ptr remix,
                               ReplaySession::shr_ptr reference) {
  DEBUG_ASSERT(remix->done_initial_exec() && reference->done_initial_exec());

  ReplayTask* remix_task = remix->current_task();
  auto prev_ip = remix_task ? remix_task->ip() : nullptr;

  auto result = remix->replay_step(RUN_SINGLESTEP);
  auto reference_result = reference->replay_step(RUN_SINGLESTEP);
  DEBUG_ASSERT(result == reference_result);

  if (!result.break_status.singlestep_complete) {
    return result;
  }

  remix_task = remix->current_task();
  ReplayTask* reference_task = reference->current_task();

  if (remix_task) {
    auto reference_regs = reference_task->regs();
    auto remix_regs = remix_task->regs();
    ASSERT(remix_task, remix_regs.matches(reference_regs))
      << "Registers mismatch, remix vs reference: " << remix_regs.compare_with(reference_regs);
    ASSERT(remix_task, remix_task->tick_count() == reference_task->tick_count())
        << "Tick count mismatch, remix=" << remix_task->tick_count()
        << " replay=" << reference_task->tick_count();
  } else {
    DEBUG_ASSERT(!reference_task);
  }
  LOG(debug) << "auto_debug completed OK at rip=" << prev_ip
             << " next=" << remix_task->ip();
  return result;
}

static shared_ptr<RemixToolHost> create_host(const string& tool_name,
                                             const vector<string>& tool_args) {
  if (!tool_args.empty()) {
    fprintf(stderr, "Unsupported tool argument: %s\n", tool_args[0].c_str());
    exit(4);
  }
  return nullptr;
}

static void ensure_initialized_remix_module(ReplayTask* rt,
                                            const string& tool_path,
                                            const MemoryRange& module_range,
                                            shared_ptr<RemixToolHost> host,
                                            intptr_t* init_cookie,
                                            RemixTestOptions test_options,
                                            bool account_for_execve) {
  if (!rt) {
    return;
  }
  auto remix_module = rt->vm()->remix_module();
  if (remix_module) {
    if (remix_module->tool_path() == tool_path) {
      return;
    }
    LOG(debug) << "Unloading tool " << remix_module->tool_path() << " at time "
               << rt->session().trace_reader().time();
    remix_module = nullptr;
    rt->vm()->unload_remix(rt);
  }

  LOG(debug) << "Loading tool " << tool_path << " at time "
             << rt->session().trace_reader().time();
  rt->vm()->load_remix(rt, module_range, tool_path, host, *init_cookie, test_options);
  auto module = rt->vm()->remix_module();
  *init_cookie = module->init_cookie_returned();
  if (account_for_execve) {
    for (auto& w : rt->post_exec_writes()) {
      module->notify_written(rt, MemoryRange(w.addr, w.data.size()));
    }
    module->did_complete_execve(rt);
  }
}

static int signal_pipe_writer;

void usr_sighandler(int) {
  char ch = 'x';
  (void)write(signal_pipe_writer, &ch, 1);
}

static ScopedFd listen_for_signals() {
  // We can't use signalfd here since we need to receive signals in this
  // process and read them from another process (potentially), so
  // use a pipe instead.
  int pipe_fds[2];
  int ret = pipe2(pipe_fds, O_CLOEXEC);
  if (ret < 0) {
    FATAL() << "Can't pipe";
  }
  signal_pipe_writer = pipe_fds[1];
  signal(SIGUSR1, usr_sighandler);
  signal(SIGUSR2, usr_sighandler);
  return ScopedFd(pipe_fds[0]);
}

static void wait_for_signal(ScopedFd& sig_fd) {
  char ch;
  int ret = read(sig_fd, &ch, 1);
  if (ret != 1) {
    FATAL() << "Failed to read from sig_fd";
  }
}

static ReplaySession::shr_ptr start_checkpoint(ReplaySession::shr_ptr& replay_session, ScopedFd& sig_fd) {
  ReplaySession::shr_ptr remix_start_session = replay_session->clone(ExposeEmuFsFiles::Exposed);
  // Print address-space-uid to real-tid map
  for (auto& vm : remix_start_session->vms()) {
    AddressSpaceUid uid = vm->uid();
    Task* t = vm->first_running_task();
    if (!t) {
      continue;
    }
    AutoRemoteSyscalls remote(t);
    long ret = remote.syscall(syscall_number_for_prctl(t->arch()),
        PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
    // If Yama isn't installed then this can return EINVAL, which is fine.
    if (ret < 0 && ret != -EINVAL) {
      errno = -ret;
      FATAL() << "PR_SET_PTRACER failed";
    }
    printf("%d %d %d %d\n", uid.tid(), uid.serial(), uid.exec_count(),
           t->tid);
  }
  printf("STARTED\n");
  fflush(stdout);
  wait_for_signal(sig_fd);
  return remix_start_session;
}

static int remix(const string& tool_name, const string& trace_dir,
                 const RemixFlags& flags, CommandForCheckpoint& command_for_checkpoint) {
  auto fds_iter = command_for_checkpoint.fds.begin();

  ScopedFd sig_fd;
  if (command_for_checkpoint.session) {
    sig_fd = move(*fds_iter);
    ++fds_iter;
  } else {
    sig_fd = listen_for_signals();
  }

  ScopedFd export_checkpoints_socket;
  // Construct the listening socket immediately so importers can connect early and block without polling.
  // If we need to import a checkpoint, we pass the socket in command_for_checkpoint.fds to the checkpoint
  // exporter's child process.
  if (flags.export_checkpoints_event) {
    if (command_for_checkpoint.session) {
      export_checkpoints_socket = move(*fds_iter);
      ++fds_iter;
    } else {
      export_checkpoints_socket = bind_export_checkpoints_socket(flags.export_checkpoints_count, flags.export_checkpoints_socket);
    }
  }

  bool use_null_tool = getenv("RR_FORCE_NULL_TOOL") != nullptr;
  bool always_remix = use_null_tool || flags.goto_event == 0;
  ReplaySession::shr_ptr replay_session;
  if (command_for_checkpoint.session) {
    replay_session = move(command_for_checkpoint.session);
  } else if (flags.import_checkpoint_socket.empty()) {
    replay_session = ReplaySession::create(trace_dir, session_flags(flags, always_remix));
  } else {
    vector<ScopedFd> fds;
    fds.push_back(move(sig_fd));
    if (flags.export_checkpoints_event) {
      fds.push_back(move(export_checkpoints_socket));
    }
    if (flags.init_cookie >= 0 && fcntl(flags.init_cookie, F_GETFD) >= 0) {
      // Assume init-cookie is the number of the fd, and send it through.
      // If it just happens to match the numer of an open fd, that's probably OK.
      fds.push_back(ScopedFd(flags.init_cookie));
    }
    return invoke_checkpoint_command(flags.import_checkpoint_socket, command_for_checkpoint.args, move(fds));
  }

  if (flags.init_cookie >= 0 && fds_iter != command_for_checkpoint.fds.end()) {
    // Duplicate fd into all tracees
    ScopedFd fd = move(*fds_iter);
    for (auto& it : replay_session->tasks()) {
      AutoRemoteSyscalls remote(it.second);
      remote.infallible_send_fd_dup(fd, flags.init_cookie, 0);
    }
  }

  ReplaySession::shr_ptr reference_session;
  ReplaySession::shr_ptr remix_start_session;
  RunCommand cmd = RUN_CONTINUE;
  // This memory range is cached in the ReplaySession so if replay_session has
  // already started, we won't retraverse the trace from here to compute it again
  // (incorrectly).
  MemoryRange module_range = replay_session->choose_remix_module_range();
  LOG(debug) << "remix module memory range is " << module_range;

  string tool_path = find_remix_module_path() + "_" + tool_name;
  string null_tool_path = find_remix_module_path() + "_NullTool";
  intptr_t init_cookie = flags.init_cookie;
  bool initialized = false;
  shared_ptr<RemixToolHost> host = create_host(tool_name, flags.tool_args);

  // We may need to start remix before executing any events.
  if (replay_session->done_initial_exec() &&
      replay_session->trace_reader().time() >= flags.goto_event) {
    if (flags.debug_event && !reference_session) {
      reference_session = replay_session->clone();
    }
    if (flags.checkpoint) {
      remix_start_session = start_checkpoint(replay_session, sig_fd);
    }
    initialized = true;

    // we don't need to account_for_execve_exit here.
    // If there is an epoch boundary just after an execve syscall exit,
    // it can't be the first execve exit, so we will have initialized remix
    // in the previous epoch and accounted for the execve effects there.
    for (auto& ts : replay_session->tasks()) {
      auto rt = static_cast<ReplayTask*>(ts.second);
      ensure_initialized_remix_module(rt, tool_path, module_range, host,
                                      &init_cookie, flags.test_options,
                                      false);
    }
  }

  while (true) {
    ReplayResult result;
    FrameTime before_time = replay_session->trace_reader().time();
    bool account_for_execve_exit =
        ReplayTask::next_event_is_execve_exit(replay_session->current_task()) &&
        before_time >= flags.goto_event;

    if (reference_session && before_time == flags.debug_event) {
      result = auto_debug(replay_session, reference_session);
    } else if (before_time == flags.singlestep_event) {
      result = replay_session->replay_step(RUN_SINGLESTEP_FAST_FORWARD);
      printf("tid:%d ", replay_session->current_task()->rec_tid);
      replay_session->current_task()->regs().print_register_file_compact(stdout);
      puts("");
    } else {
      result = replay_session->replay_step(cmd);
      DEBUG_ASSERT(result.break_status.watchpoints_hit.empty());
      DEBUG_ASSERT(!result.break_status.breakpoint_hit);
      DEBUG_ASSERT(!result.break_status.singlestep_complete);
      if (reference_session) {
        auto reference_result = reference_session->replay_step(cmd);
        DEBUG_ASSERT(reference_result == result);
      }
    }

    if (result.status == REPLAY_EXITED) {
      break;
    }
    FrameTime after_time = replay_session->trace_reader().time();
    if (flags.stop_event &&
        after_time >= flags.stop_event) {
      auto rt = static_cast<ReplayTask*>(replay_session->current_task());
      // NB: It is possible for this to be the very first time remix is used
      // (e.g. if this task is not executed at all in this shard but does
      // have a syscall-exit event at `stop_event`). So make sure that remix
      // is initialized before we call into it.
      ensure_initialized_remix_module(rt, tool_path, module_range, host,
                                      &init_cookie, flags.test_options,
                                      account_for_execve_exit);
      rt->vm()->remix_module()->notify_will_exit(rt, true);
      break;
    }
    DEBUG_ASSERT(result.status == REPLAY_CONTINUE);

    if (replay_session->done_initial_exec() && !initialized &&
        after_time >= flags.goto_event) {
      // XXX at some point we could support cloning sessions containing
      // remix modules. Right now we don't, because recreating shared mmaps
      // notifies modules and havoc ensues.
      // Unload any NullTool modules we have running.
      replay_session->unload_remix();

      if (flags.debug_event && !reference_session) {
        reference_session = replay_session->clone();
      }
      if (flags.checkpoint) {
        remix_start_session = start_checkpoint(replay_session, sig_fd);
      }
      initialized = true;

      for (auto& ts : replay_session->tasks()) {
        auto rt = static_cast<ReplayTask*>(ts.second);
        ensure_initialized_remix_module(rt, tool_path, module_range, host,
                                        &init_cookie, flags.test_options,
                                        account_for_execve_exit);
      }
    } else if (initialized) {
      // If a task has just execed, ensure we initialize it for remix
      auto rt = replay_session->current_task();
      ensure_initialized_remix_module(rt, tool_path, module_range, host,
                                      &init_cookie, flags.test_options,
                                      account_for_execve_exit);
    } else if (replay_session->done_initial_exec() && use_null_tool) {
      auto rt = replay_session->current_task();
      ensure_initialized_remix_module(rt, null_tool_path, module_range, host,
                                      &init_cookie, flags.test_options,
                                      account_for_execve_exit);
    }

    if (after_time == flags.export_checkpoints_event) {
      command_for_checkpoint = export_checkpoints(move(replay_session), flags.export_checkpoints_count,
          export_checkpoints_socket, flags.export_checkpoints_socket);
      return 0;
    }
  }

  if (flags.wait_on_close) {
    // Get remix modules into their up-to-date state before we notify
    // that the session has completed.
    replay_session->flush_remix_module_state();
    printf("EXITED\n");
    fflush(stdout);
    wait_for_signal(sig_fd);
  }

  return 0;
}

static bool parse_tool(vector<string>& args, string* out) {
  if (!Command::verify_not_option(args)) {
    return false;
  }
  *out = args[0];
  args.erase(args.begin());
  return true;
}

int RemixCommand::run_internal(CommandForCheckpoint& command_for_checkpoint) {
  bool found_dir = false;
  string trace_dir;
  bool found_tool = false;
  string tool_name;
  RemixFlags flags;
  vector<string> args = command_for_checkpoint.args;

  while (!args.empty()) {
    if (parse_remix_arg(args, flags)) {
      continue;
    }
    if (!found_tool && parse_tool(args, &tool_name)) {
      found_tool = true;
      continue;
    }
    if (!found_dir && parse_optional_trace_dir(args, &trace_dir)) {
      found_dir = true;
      continue;
    }
    flags.tool_args.push_back(args[0]);
    args.erase(args.begin(), args.begin() + 1);
  }

  if (!found_tool) {
    print_help(stderr);
    return 1;
  }
  if (flags.export_checkpoints_event) {
    if (flags.wait_on_close) {
      fprintf(stderr, "Can't use --wait-on-close with --export-checkpoints\n");
      return 1;
    }
    if (flags.checkpoint) {
      fprintf(stderr, "Can't use --checkpoint with --export-checkpoints\n");
      return 1;
    }
  }

  assert_prerequisites();

  if (flags.goto_event > 0 && flags.stop_event > 0 &&
      flags.goto_event > flags.stop_event) {
    fprintf(stderr, "rr: remix --stop <event> must be later than --goto <event>\n");
    return 1;
  }

  if (running_under_rr()) {
    if (!Flags::get().suppress_environment_warnings) {
      fprintf(stderr, "rr: rr pid %d running under parent %d. Good luck.\n",
              getpid(), getppid());
    }
    if (trace_dir.empty()) {
      fprintf(stderr,
              "rr: No trace-dir supplied. You'll try to replay the "
              "recording of this rr and have a bad time. Bailing out.\n");
      return 3;
    }
  }

  return remix(tool_name, trace_dir, flags, command_for_checkpoint);
}

int RemixCommand::run(vector<string>& args) {
  CommandForCheckpoint command_for_checkpoint;
  command_for_checkpoint.args = move(args);
  while (true) {
    ScopedFd exit_notification_fd = move(command_for_checkpoint.exit_notification_fd);
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
