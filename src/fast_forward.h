/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_FAST_FORWARD_H_
#define RR_FAST_FORWARD_H_

class Task;
class Registers;

/**
 * Perform one or more synchronous singlesteps of |t|. Usually just does
 * one singlestep, except when a singlestep leaves the IP unchanged (i.e. a
 * single instruction represents a loop, such as an x86 REP-prefixed string
 * instruction).
 *
 * We always perform at least one singlestep. We stop after a singlestep if
 * one of the following is true, or will be true after one more singlestep:
 * -- Any breakpoint or watchpoint has been triggered
 * -- IP has advanced to the next instruction
 * -- One of the register states in |states| (a null-terminated list)
 * has been reached.
 *
 * Spurious returns after any singlestep are also allowed.
 */
void fast_forward_through_instruction(Task* t, const Registers** states);

#endif // RR_FAST_FORWARD_H_
