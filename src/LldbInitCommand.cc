/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "Command.h"
#include "GdbServer.h"
#include "launch_debugger.h"
#include "main.h"

using namespace std;

namespace rr {

class LldbInitCommand : public Command {
public:
  virtual int run(vector<string>& args) override;

protected:
  LldbInitCommand(const char* name, const char* help) : Command(name, help) {}

  static LldbInitCommand singleton;
};

LldbInitCommand LldbInitCommand::singleton("lldbinit", " rr lldbinit\n");

int LldbInitCommand::run(vector<string>& args) {
  while (parse_global_option(args)) {
  }

  puts("# This is a Python script. Save it to a file and run it from LLDB using");
  puts("#     script exec(open('<filename>').read())");
  puts("# or similar.");
  fputs(lldb_init_script().c_str(), stdout);
  return 0;
}

} // namespace rr
