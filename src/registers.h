/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef RR_REGISTERS_H_
#define RR_REGISTERS_H_

#include <sys/user.h>

/**
 * A Registers object contains values for all general-purpose registers.
 *
 * When reading register values, be sure to cast the result to the correct
 * type according to the kernel docs. E.g. int values should be cast
 * to int explicitly (or implicitly, by assigning to an int-typed variable),
 * size_t should be cast to size_t, etc. If the type is signed, call the
 * _signed getter. This ensures that when building rr 64-bit we will use the
 * right number of register bits whether the tracee is 32-bit or 64-bit, and
 * get sign-extension right.
 */
class Registers: public user_regs_struct {
};

#endif /* RR_REGISTERS_H_ */
