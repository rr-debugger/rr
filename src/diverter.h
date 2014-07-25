/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef RR_DIVERTER_H_
#define RR_DIVERTER_H_

#include "types.h"

/**
 * rr's "diverter" mode implements a third type of execution
 * control, in addition to "recorder" and "replayer".
 *
 * Diverter allows tracees to execute freely, as in "recorder"
 * mode, but doesn't attempt to record any data.  Diverter
 * emulates the syscalls it's able to (such as writes to stdio fds),
 * and essentially ignores the syscalls it doesn't know how to
 * implement.  Tracees can easily get into inconsistent states within
 * diversion mode, and no attempt is made to detect or rectify that.
 *
 * Diverter mode is designed to support short-lived diversions from
 * "replayer" sessions, as required to support gdb's |call foo()|
 * feature.  A diversion is created for the call frame, then discarded
 * when the call finishes (loosely speaking).
 *
 * TODO: it would probably be cleaner and simpler to make separate
 * *Session classes for each execution-control domain: RecordSession,
 * ReplaySession, and DiversionSession, then make execution control
 * part of those session classes.  That would entail creating
 * {record,replay,diversion}_session.cc files, and folding
 * {recorder,replayer,diverter}.cc into those as appropriate.
 */

struct dbg_context;
struct dbg_request;
class ReplaySession;

/**
 * Create a new diversion session using |replay| session as the
 * template.  The |replay| session isn't mutated.
 *
 * Execution begins in the new diversion session under the control of
 * |dbg| starting with initial thread target |task|.  The diversion
 * session ends at the request of |dbg|, and |req| returns the first
 * request made that wasn't handled by the diversion session.  That
 * is, the first request that should be handled by |replay| upon
 * resuming execution in that session.
 */
void divert(ReplaySession& replay, struct dbg_context* dbg, pid_t task,
	    struct dbg_request* req);

#endif // RR_DIVERTER_H_
