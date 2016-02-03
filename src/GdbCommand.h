/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_GDB_COMMAND_H_
#define RR_GDB_COMMAND_H_

#include "GdbServer.h"
#include "GdbCommandHandler.h"

#include <sstream>
#include <string>
#include <vector>

class GdbCommand {
protected:
  GdbCommand(const std::string& cmd_name) : cmd_name(cmd_name) {
    GdbCommandHandler::register_command(*this);
  }

public:
  virtual ~GdbCommand() {}

  const std::string& name() const { return cmd_name; }

  /**
   * Handle the RR Cmd and return a string response to be echo'd
   * to the user.
   *
   * NOTE: args[0] is the command name
   */
  virtual std::string invoke(GdbServer& gdb_server, Task* t,
                             const std::vector<std::string>& args) = 0;

  /**
   * When call, gdb will automatically fill argument to this command
   * by running gdb.execute(). This is useful to gdb state along side
   * of the command invocation.
   */
  void add_auto_args(const std::string& auto_arg) {
    cmd_auto_args.push_back(auto_arg);
  }

  const std::vector<std::string>& auto_args() const { return cmd_auto_args; }

  /**
   * Setup all the automatic auto_args for our commands.
   */
  static void init_auto_args();

private:
  const std::string cmd_name;
  std::vector<std::string> cmd_auto_args;
};

class SimpleGdbCommand : public GdbCommand {
public:
  SimpleGdbCommand(
      const std::string& cmd_name,
      const std::function<std::string(
          GdbServer&, Task* t, const std::vector<std::string>&)>& invoker)
      : GdbCommand(cmd_name), invoker(invoker) {}

  virtual std::string invoke(GdbServer& gdb_server, Task* t,
                             const std::vector<std::string>& args) {
    return invoker(gdb_server, t, args);
  }

  std::function<std::string(GdbServer&, Task* t,
                            const std::vector<std::string>&)> invoker;
};

#define RR_LINE_CONCAT(str, line) str##line
#define RR_LINE_EXPAND(str, line) RR_LINE_CONCAT(str, line)
#define RR_CMD_OBJ() RR_LINE_EXPAND(sRRCmdObj, __LINE__)

#define RR_CMD(id, name)                                                       \
  class id : public GdbCommand {                                               \
  public:                                                                      \
    id() : GdbCommand(name) {}                                                 \
                                                                               \
  private:                                                                     \
    virtual std::string invoke(GdbServer& gdb_server, Task* t,                 \
                               const std::vector<std::string>& args);          \
  };                                                                           \
                                                                               \
  static id RR_CMD_OBJ();                                                      \
                                                                               \
  std::string id::invoke(GdbServer& gdb_server, Task* t,                       \
                         const std::vector<std::string>& args)

#endif
