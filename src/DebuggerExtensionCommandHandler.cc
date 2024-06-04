/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "DebuggerExtensionCommandHandler.h"
#include "GdbCommand.h"
#include "log.h"

#include <sstream>
#include <vector>

using namespace std;

namespace rr {

// HashMap would be better here but the unordered_map API is annoying
// and linear search is fine.
static vector<GdbCommand*>* gdb_command_list;

static string gdb_macro_binding(const GdbCommand& cmd) {
  string auto_args_str = "[";
  for (size_t i = 0; i < cmd.auto_args().size(); i++) {
    if (i > 0) {
      auto_args_str += ", ";
    }
    auto_args_str += "'" + cmd.auto_args()[i] + "'";
  }
  auto_args_str += "]";
  string ret = "python RRCmd('" + cmd.name() + "', " + auto_args_str + ")\n";
  if (!cmd.docs().empty()) {
    ret += "document " + cmd.name() + "\n" + cmd.docs() + "\nend\n";
  }
  return ret;
}

/* static */ string DebuggerExtensionCommandHandler::gdb_macros() {
  GdbCommand::init_auto_args();
  stringstream ss;
  ss << string(R"Delimiter(

set python print-stack full
python

import re

def gdb_unescape(string):
    str_len = len(string)
    if str_len % 2: # check for unexpected string length
        return ""
    result = bytearray()
    try:
        pos = 0
        while pos < str_len:
            hex_char = string[pos:pos+2]
            result.append(int(hex_char, 16))
            pos += 2
    except: # check for unexpected string value
        return ""
    return result.decode('utf-8')

def gdb_escape(string):
    result = ""
    for curr_char in string.encode('utf-8'):
        if isinstance(curr_char, str):
            curr_char = ord(curr_char)
        result += format(curr_char, '02x')
    return result

class RRWhere(gdb.Command):
    """Helper to get the location for checkpoints/history. Used by auto-args"""
    def __init__(self):
        gdb.Command.__init__(self, 'rr-where',
                             gdb.COMMAND_USER, gdb.COMPLETE_NONE, False)

    def invoke(self, arg, from_tty):
#Get the symbol name from 'frame 0' in the format:
# '#0  0x00007f9d81a04c46 in _dl_start (arg=0x7ffee1f1c740) at rtld.c:356
# 356 in rtld.c'
        try:
            rv = gdb.execute('frame 0', to_string=True)
        except:
            rv = "???" # This may occurs if we're not running
        m = re.match(r"#0\w*(.*)", rv);
        if m:
            rv = m.group(1)
        else:
            rv = rv + "???"
        gdb.write(rv)

RRWhere()

class RRDenied(gdb.Command):
    """Helper to prevent use of breaking commands. Used by auto-args"""
    def __init__(self):
        gdb.Command.__init__(self, 'rr-denied',
                             gdb.COMMAND_USER, gdb.COMPLETE_NONE, False)

    def invoke(self, arg, from_tty):
        raise gdb.GdbError("Execution of '" + arg + "' is not possible in recorded executions.")

RRDenied()

class RRCmd(gdb.Command):
    def __init__(self, name, auto_args):
        gdb.Command.__init__(self, name,
                             gdb.COMMAND_USER, gdb.COMPLETE_NONE, False)
        self.cmd_name = name
        self.auto_args = auto_args

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        self.rr_cmd(args)

    def rr_cmd(self, args):
        # Ensure gdb tells rr its current thread
        curr_thread = gdb.selected_thread()
        cmd_prefix = ("maint packet qRRCmd:%s:%d"%
            (self.cmd_name, -1 if curr_thread is None else curr_thread.ptid[1]))
        arg_strs = []
        for auto_arg in self.auto_args:
            arg_strs.append(":" + gdb_escape(gdb.execute(auto_arg, to_string=True)))
        for arg in args:
            arg_strs.append(":" + gdb_escape(arg))
        rv = gdb.execute(cmd_prefix + ''.join(arg_strs), to_string=True);
        rv_match = re.search('received: "(.*)"', rv, re.MULTILINE);
        if not rv_match:
            gdb.write("Response error: " + rv)
            return
        response = gdb_unescape(rv_match.group(1))
        if response != '\n':
            gdb.write(response)

def history_push(p):
    # ensure any output (e.g. produced by breakpoint commands running during our
    # processing, that were triggered by the stop we've been notified for)
    # is echoed as normal.
    gdb.execute("rr-history-push")

rr_suppress_run_hook = False

class RRHookRun(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 'rr-hook-run',
                             gdb.COMMAND_USER, gdb.COMPLETE_NONE, False)
        
    def invoke(self, arg, from_tty):  
      thread = int(gdb.parse_and_eval("$_thread"))
      if thread != 0 and not rr_suppress_run_hook:
        gdb.execute("stepi")
     
class RRSetSuppressRunHook(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 'rr-set-suppress-run-hook',
                             gdb.COMMAND_USER, gdb.COMPLETE_NONE, False)
        
    def invoke(self, arg, from_tty):
      rr_suppress_run_hook = arg == '1'

RRHookRun()
RRSetSuppressRunHook()

#Automatically push an history entry when the program execution stops
#(signal, breakpoint).This is fired before an interactive prompt is shown.
#Disabled for now since it's not fully working.
gdb.events.stop.connect(history_push)

end
)Delimiter");

  if (gdb_command_list) {
    for (auto& it : *gdb_command_list) {
      ss << gdb_macro_binding(*it);
    }
  }

  ss << string(R"Delimiter(
define hookpost-back
maintenance flush register-cache
frame
end

define hookpost-forward
maintenance flush register-cache
frame
end
)Delimiter");

  return ss.str();
}

/*static*/ GdbCommand* DebuggerExtensionCommandHandler::command_for_name(const string& name) {
  if (!gdb_command_list) {
    return nullptr;
  }
  for (auto& it : *gdb_command_list) {
    if (it->name() == name) {
      return it;
    }
  }
  return nullptr;
}

void DebuggerExtensionCommandHandler::register_command(GdbCommand& cmd) {
  LOG(debug) << "registering command: " << cmd.name();
  if (!gdb_command_list) {
    gdb_command_list = new vector<GdbCommand*>();
  }
  gdb_command_list->push_back(&cmd);
}

// applies the simplest two hex character by byte encoding
static string gdb_escape(const string& str) {
  stringstream ss;
  ss << hex;
  const size_t len = str.size();
  const char *data = str.data();
  for (size_t i = 0; i < len; i++) {
    int chr = (uint8_t)data[i];
    if (chr < 16) {
      ss << "0";
    }
    ss << chr;
  }
  return ss.str();
}
// undo the two hex character byte encoding,
// in case of error returns an empty string
static string gdb_unescape(const string& str) {
  const size_t len = str.size();
  // check for unexpected string length
  if (len % 2) {
    return "";
  }
  stringstream ss;
  for (size_t i = 0; i < len; i += 2) {
    string substr = str.substr(i, 2);
    const char *hex_str = substr.c_str();
    char *ptr = nullptr;
    ss << (char)strtoul(hex_str, &ptr, 16);
    // check for unexpected character
    if (*ptr) {
      return "";
    }
  }
  return ss.str();
}

/* static */ string DebuggerExtensionCommandHandler::process_command(GdbServer& gdb_server,
                                                       Task* t,
                                                       const GdbRequest::RRCmd& rr_cmd) {
  vector<string> args;
  for (const auto& arg : rr_cmd.args) {
    args.push_back(gdb_unescape(arg));
  }

  GdbCommand* cmd = command_for_name(rr_cmd.name);
  if (!cmd) {
    return gdb_escape(string() + "Command '" + rr_cmd.name + "' not found.\n");
  }
  LOG(debug) << "invoking command: " << cmd->name();
  Task* target = t->session().find_task(rr_cmd.target_tid);
  
  // perhaps not the best option, but better than a nullptr
  if (target == nullptr) target = t;
  
  string resp = cmd->invoke(gdb_server, target, args);

  if (resp == DebuggerExtensionCommandHandler::cmd_end_diversion()) {
    LOG(debug) << "cmd must run outside of diversion (" << resp << ")";
    return resp;
  }

  LOG(debug) << "cmd response: " << resp;
  return gdb_escape(resp + "\n");
}

} // namespace rr
