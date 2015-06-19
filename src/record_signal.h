/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_HANDLE_SIGNAL_H__
#define RR_HANDLE_SIGNAL_H__

#include <signal.h>

class Task;

const int SIGCHLD_SYNTHETIC = 0xbeadf00d;

void disarm_desched_event(Task* t);
void arm_desched_event(Task* t);

enum SignalHandled { SIGNAL_HANDLED, SIGNAL_PTRACE_STOP, DEFER_SIGNAL };
/**
 * Handle the given signal for |t|.
 * Returns SIGNAL_HANDLED if we handled the signal, SIGNAL_PTRACE_STOP if we
 * didn't handle the signal due to an emulated ptrace-stop, and SIGNAL_DEFER
 * if we can't handle the signal right now and should try calling
 * handle_signal again later in task execution.
 * Handling the signal means we either pushed a new signal event, new
 * desched + syscall-interruption events, or no-op.
 */
SignalHandled handle_signal(Task* t, siginfo_t* si);

#endif /* RR_HANDLE_SIGNAL_H__ */
