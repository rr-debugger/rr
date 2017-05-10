/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "Command.h"
#include "GdbServer.h"
#include "main.h"

using namespace std;

namespace rr {

class GdbInitCommand : public Command {
public:
  virtual int run(vector<string>& args) override;

protected:
  GdbInitCommand(const char* name, const char* help) : Command(name, help) {}

  static GdbInitCommand singleton;
};

GdbInitCommand GdbInitCommand::singleton("gdbinit", " rr gdbinit\n");

int GdbInitCommand::run(vector<string>& args) {
  while (parse_global_option(args)) {
  }

  fputs(GdbServer::init_script().c_str(), stdout);
  return 0;
}

} // namespace rr
