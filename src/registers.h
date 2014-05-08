/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef RR_REGISTERS_H_
#define RR_REGISTERS_H_

#include <stdint.h>
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
public:
	uintptr_t ip() const { return eip; }
	void set_ip(uintptr_t addr) { eip = addr; }
	uintptr_t sp() const { return esp; }
	void set_sp(uintptr_t addr) { esp = addr; }

	// Access the registers holding system-call numbers, results, and
	// parameters.

	intptr_t syscallno() const { return eax; }
	void set_syscallno(intptr_t syscallno) { eax = syscallno; }

	uintptr_t syscall_result() const { return eax; }
	intptr_t syscall_result_signed() const { return eax; }
	void set_syscall_result(uintptr_t syscall_result) {
		eax = syscall_result;
	}

	/**
	 * This pseudo-register holds the system-call number when we get ptrace
	 * enter-system-call and exit-system-call events. Setting it changes
	 * the system-call executed when resuming after an enter-system-call
	 * event.
	 */
	intptr_t original_syscallno() const { return orig_eax; }
	void set_original_syscallno(intptr_t syscallno) {
		orig_eax = syscallno;
	}

	uintptr_t arg1() const { return ebx; }
	intptr_t arg1_signed() const { return ebx; }
	void set_arg1(uintptr_t value) { ebx = value; }

	uintptr_t arg2() const { return ecx; }
	intptr_t arg2_signed() const { return ecx; }
	void set_arg2(uintptr_t value) { ecx = value; }

	uintptr_t arg3() const { return edx; }
	intptr_t arg3_signed() const { return edx; }
	void set_arg3(uintptr_t value) { edx = value; }

	uintptr_t arg4() const { return esi; }
	intptr_t arg4_signed() const { return esi; }
	void set_arg4(uintptr_t value) { esi = value; }

	uintptr_t arg5() const { return edi; }
	intptr_t arg5_signed() const { return edi; }
	void set_arg5(uintptr_t value) { edi = value; }

	uintptr_t arg6() const { return ebp; }
	intptr_t arg6_signed() const { return ebp; }
	void set_arg6(uintptr_t value) { ebp = value; }
};

#endif /* RR_REGISTERS_H_ */
