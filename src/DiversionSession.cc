/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "DiversionSession"

#include "DiversionSession.h"

#include "ReplaySession.h"

using namespace rr;

DiversionSession::DiversionSession(const ReplaySession& other)
    : emu_fs(other.emufs().clone()) {}

DiversionSession::~DiversionSession() {
  // We won't permanently leak any OS resources by not ensuring
  // we've cleaned up here, but sessions can be created and
  // destroyed many times, and we don't want to temporarily hog
  // resources.
  kill_all_tasks();
  assert(tasks().size() == 0 && vms().size() == 0);
  emu_fs->gc(*this);
  assert(emu_fs->size() == 0);
}

DiversionSession::DiversionResult DiversionSession::diversion_step(
    RunCommand command) {
  DiversionResult result;
  return result;
}
