/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_HANDLE_SIGNAL_H__
#define RR_HANDLE_SIGNAL_H__

#include <signal.h>

class Task;

const int SIGCHLD_SYNTHETIC = 0xbeadf00d;

/**
 * Handle the pending signal for |t|.  To force delivery/handling of a
 * particular signal, pass a pointer to the siginfo in |si|.
 * Otherwise this function determines the pending signal info.
 */
void handle_signal(Task* t, siginfo_t* si);

#endif /* RR_HANDLE_SIGNAL_H__ */
