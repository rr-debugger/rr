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

#define RR_CMD_AUTO(id, name, ...)                                             \
  class id : public GdbCommand {                                               \
  public:                                                                      \
    id() : GdbCommand(name) {}                                                 \
                                                                               \
  private:                                                                     \
    virtual std::string invoke(GdbServer& gdb_server, Task* t,                 \
                               const std::vector<std::string>& args);          \
    std::string command(GdbServer& gdb_server, Task* t, __VA_ARGS__);          \
  };                                                                           \
                                                                               \
  static id RR_CMD_OBJ();                                                      \
                                                                               \
  std::string id::invoke(GdbServer& gdb_server, Task* t,                       \
                         const std::vector<std::string>& args) {               \
    return DispatchTo(&id::command, this, gdb_server, t, args);                \
  }                                                                            \
  std::string id::command(GdbServer& gdb_server, Task* t, __VA_ARGS__)

template <typename Target>
bool cast(const std::string& s, Target& out_target, std::string& error_msg) {
  std::stringstream ss(s);
  ss >> out_target;
  if (!ss || ss.peek() != EOF) {
    error_msg = std::string() + "Error: Cannot cast '" + s + "' to type '" +
                typeid(Target).name() + "'\n";
    return false;
  }
  return true;
}

template <>
bool cast(const std::string& s, std::string& out_target,
          std::string& error_msg);

template <typename clazz>
std::string DispatchTo(std::string (clazz::*func)(GdbServer&, Task*), clazz* c,
                       GdbServer& gdb_server, Task* t,
                       const std::vector<std::string>& args) {
  if (args.size() != 1) {
    return "Error: bad number of argument(s), expecting 0\n";
  }
  return (c->*func)(gdb_server, t);
}

template <typename clazz, typename A1>
std::string DispatchTo(std::string (clazz::*func)(GdbServer&, Task*, A1),
                       clazz* c, GdbServer& gdb_server, Task* t,
                       const std::vector<std::string>& args) {
  if (args.size() != 2) {
    return "Error: bad number of argument(s), expecting 1\n";
  }
  A1 arg1;
  std::string error_msg;
  if (!cast<A1>(args[1], arg1, error_msg)) {
    return error_msg;
  }
  return (c->*func)(gdb_server, t, arg1);
}

template <typename clazz, typename A1, typename A2>
std::string DispatchTo(std::string (clazz::*func)(GdbServer&, Task*, A1, A2),
                       clazz* c, GdbServer& gdb_server, Task* t,
                       const std::vector<std::string>& args) {
  if (args.size() != 3) {
    return "Error: bad number of argument(s), expecting 2\n";
  }
  A1 arg1;
  std::string error_msg;
  if (!cast<A1>(args[1], arg1, error_msg)) {
    return error_msg;
  }
  A2 arg2;
  if (!cast<A2>(args[2], arg2, error_msg)) {
    return error_msg;
  }
  return (c->*func)(gdb_server, t, arg1, arg2);
}

template <typename clazz, typename A1, typename A2, typename A3>
std::string DispatchTo(std::string (clazz::*func)(A1, A2, A3), clazz* c,
                       GdbServer& gdb_server, Task* t,
                       const std::vector<std::string>& args) {
  if (args.size() != 4) {
    return "Error: bad number of argument(s), expecting 3\n";
  }
  A1 arg1;
  std::string error_msg;
  if (!cast<A1>(args[1], arg1, error_msg)) {
    return error_msg;
  }
  A2 arg2;
  if (!cast<A2>(args[2], arg2, error_msg)) {
    return error_msg;
  }
  A3 arg3;
  if (!cast<A3>(args[3], arg3, error_msg)) {
    return error_msg;
  }
  return (c->*func)(gdb_server, t, arg1, arg2, arg3);
}

#endif
