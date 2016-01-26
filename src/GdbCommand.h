/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_GDB_COMMAND_H_
#define RR_GDB_COMMAND_H_

#include "GdbServer.h"
#include "GdbCommandHandler.h"

#include <string>
#include <vector>

class GdbCommand {
protected:
  GdbCommand(const std::string& cmd_name)
    : cmd_name(cmd_name) {
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
  virtual std::string invoke(GdbServer& gdb_server, Task* t, const std::vector<std::string>& args) = 0;

private:
  const std::string cmd_name;
};

#define RR_LINE_CONCAT(str, line) str ## line
#define RR_LINE_EXPAND(str, line) RR_LINE_CONCAT(str, line)
#define RR_CMD_CLASSNAME(name) RR_LINE_EXPAND(RRCmd, __LINE__)
#define RR_CMD_OBJ(name) RR_LINE_EXPAND(sRRCmdObj, __LINE__)

#define RR_CMD(name) \
class RR_CMD_CLASSNAME(name) : public GdbCommand {\
public:\
  RR_CMD_CLASSNAME(name)()\
    : GdbCommand(#name) {}\
private:\
  virtual std::string invoke(GdbServer& gdb_server, Task* t, const std::vector<std::string>& args);\
};\
\
static RR_CMD_CLASSNAME(name) RR_CMD_OBJ(name);\
\
std::string RR_CMD_CLASSNAME(name)::invoke(GdbServer& gdb_server, Task* t, const std::vector<std::string>& args)

#endif
