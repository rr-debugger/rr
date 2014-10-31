/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_REPLAYER_H_
#define RR_REPLAYER_H_

#include "Ticks.h"
#include "util.h"

struct GdbContext;
struct dbg_request;
class ReplaySession;
class Session;

/**
 * Replay the trace.  argc, argv, and envp are this process's
 * parameters.
 * Returns an exit code: 0 on success.
 */
int replay(int argc, char* argv[], char** envp);

/**
 * Process the single debugger request |req|, made by |dbg| targeting
 * |t|, inside the session |session|.
 *
 * Callers should implement any special semantics they want for
 * particular debugger requests before calling this helper, to do
 * generic processing.
 */
void dispatch_debugger_request(Session& session, struct GdbContext* dbg,
                               Task* t, const struct dbg_request& req);

/**
 * Return true if |sig| is a signal that may be generated during
 * replay but should be ignored.  For example, SIGCHLD can be
 * delivered at almost point during replay when tasks exit, but it's
 * not part of the recording and shouldn't be delivered.
 *
 * TODO: can we do some clever sigprocmask'ing to avoid pending
 * signals altogether?
 */
bool is_ignored_replay_signal(int sig);

bool trace_instructions_up_to_event(uint64_t event);

/**
 * Start a debugging connection for |t| and return when there are no
 * more requests to process (usually because the debugger detaches).
 *
 * Unlike |emergency_debug()|, this helper doesn't attempt to
 * determine whether blocking rr on a debugger connection might be a
 * bad idea.  It will always open the debug socket and block awaiting
 * a connection.
 */
void start_debug_server(Task* t);

#endif /* RR_REPLAYER_H_ */
