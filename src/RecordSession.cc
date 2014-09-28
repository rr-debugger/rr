/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "RecordSession"

#include "RecordSession.h"

#include "task.h"

using namespace rr;
using namespace std;

Task* RecordSession::create_task() {
  Task* t = Task::spawn(*this);
  track(t);
  return t;
}

/*static*/ RecordSession::shr_ptr RecordSession::create(
    const std::vector<std::string>& argv, const std::vector<std::string>& envp,
    const string& cwd, int bind_to_cpu) {
  shr_ptr session(new RecordSession(argv, envp, cwd, bind_to_cpu));
  return session;
}

RecordSession::RecordSession(const std::vector<std::string>& argv,
                             const std::vector<std::string>& envp,
                             const string& cwd, int bind_to_cpu)
    : trace_out(argv, envp, cwd, bind_to_cpu) {}
