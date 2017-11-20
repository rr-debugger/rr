/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_GDB_COMMAND_H_
#define RR_GDB_COMMAND_H_

#include "GdbCommandHandler.h"
#include "GdbServer.h"

#include <sstream>
#include <string>
#include <vector>

namespace rr {

class GdbCommand {
protected:
  GdbCommand(const std::string& cmd_name, const std::string& documentation)
      : cmd_name(cmd_name), documentation(documentation) {
    GdbCommandHandler::register_command(*this);
  }

public:
  virtual ~GdbCommand() {}

  const std::string& name() const { return cmd_name; }
  const std::string& docs() const { return documentation; }

  /**
   * Handle the RR Cmd and return a string response to be echo'd
   * to the user.
   *
   * NOTE: args[0] is the command name
   */
  virtual std::string invoke(GdbServer& gdb_server, Task* t,
                             const std::vector<std::string>& args) = 0;

  /**
   * When called, gdb will automatically run gdb.execute() on this string and
   * pass it as an argument to the rr command. This is useful to pass gdb
   * state alongside the command invocation.
   */
  void add_auto_arg(const std::string& auto_arg) {
    cmd_auto_args.push_back(auto_arg);
  }

  const std::vector<std::string>& auto_args() const { return cmd_auto_args; }

  /**
   * Setup all the automatic auto_args for our commands.
   */
  static void init_auto_args();

private:
  const std::string cmd_name;
  const std::string documentation;
  std::vector<std::string> cmd_auto_args;
};

class SimpleGdbCommand : public GdbCommand {
public:
  SimpleGdbCommand(
      const std::string& cmd_name, const std::string& documentation,
      const std::function<std::string(
          GdbServer&, Task* t, const std::vector<std::string>&)>& invoker)
      : GdbCommand(cmd_name, documentation), invoker(invoker) {}

  virtual std::string invoke(GdbServer& gdb_server, Task* t,
                             const std::vector<std::string>& args) override {
    return invoker(gdb_server, t, args);
  }

  std::function<std::string(GdbServer&, Task* t,
                            const std::vector<std::string>&)>
      invoker;
};

} // namespace rr

#endif
