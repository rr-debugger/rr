/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "log.h"

#include "GdbServer.h"
#include "RecordSession.h"

static void emergency_debug(Task* t) {
  RecordSession* record_session = t->session().as_record();
  if (record_session) {
    record_session->trace_writer().close();
  }

  if (probably_not_interactive() && !Flags::get().force_things) {
    errno = 0;
    FATAL()
        << "(session doesn't look interactive, aborting emergency debugging)";
  }

  GdbServer::emergency_debug(t);
  FATAL() << "Can't resume execution from invalid state";
}

EmergencyDebugOstream::~EmergencyDebugOstream() {
  log_stream() << std::endl;
  t->log_pending_events();
  emergency_debug(t);
}
