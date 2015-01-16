/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_HANDLE_SIGNAL_H__
#define RR_HANDLE_SIGNAL_H__

#include <signal.h>

class Task;

const int SIGCHLD_SYNTHETIC = 0xbeadf00d;

/**
 * Handle the next stashed signal for |t|.
 */
void handle_signal(Task* t);

#endif /* RR_HANDLE_SIGNAL_H__ */
