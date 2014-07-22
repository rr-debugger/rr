/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef RR_EXPERIMENTER_H_
#define RR_EXPERIMENTER_H_

#include "types.h"

/**
 * rr's "experimenter" mode implements a third type of execution
 * control, in addition to "recorder" and "replayer".
 *
 * Experimenter allows tracees to execute freely, as in "recorder"
 * mode, but doesn't attempt to record any data.  Experimenter
 * emulates the syscalls it's able to (such as writes to stdio fds),
 * and essentially ignores the syscalls it doesn't know how to
 * implement.  Tracees can easily get into inconsistent states within
 * experiment mode, and no attempt is made to detect or rectify that.
 *
 * Experimenter mode is designed to support short-lived diversions
 * from "replayer" sessions, as required to support gdb's |call foo()|
 * feature.  An experiment is created for the call frame, then
 * discarded when the call finishes (loosely speaking).
 *
 * TODO: it would probably be cleaner and simpler to make separate
 * *Session classes for each execution-control domain: RecordSession,
 * ReplaySession, and ExperimentSession, then make execution control
 * part of those session classes.  That would entail creating
 * {record,replay,experiment}_session.cc files, and folding
 * {recorder,replayer,experimenter}.cc into those as appropriate.
 */

struct dbg_context;
struct dbg_request;
class ReplaySession;

/**
 * Create a new experiment session using |replay| session as the
 * template.  (The |replay| session isn't mutated though.)
 *
 * Execution begins in the new experiment session under the control of
 * |dbg| starting with initial thread target |task|.  The experiment
 * session ends at the request of |dbg|, and |req| returns the first
 * request made that wasn't handled by the experiment session.  That
 * is, the first request that should be handled by |replay| upon
 * resuming execution in that session.
 */
void experiment(ReplaySession& replay, struct dbg_context* dbg, pid_t task,
		struct dbg_request* req);

#endif // RR_EXPERIMENTER_H_
