/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef RR_REGISTERS_H_
#define RR_REGISTERS_H_

#include <stddef.h>
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

	// Various things the GDB stub needs to know about.
	enum DebuggerRegister {
		DREG_EAX, DREG_ECX, DREG_EDX, DREG_EBX,
		DREG_ESP, DREG_EBP, DREG_ESI, DREG_EDI,
		DREG_EIP, DREG_EFLAGS,
		DREG_CS, DREG_SS, DREG_DS, DREG_ES, DREG_FS, DREG_GS,
		DREG_ST0,
		/* Last register we can find in user_regs_struct (except for
		 * orig_eax). */
		DREG_NUM_USER_REGS = DREG_GS + 1,
		DREG_MXCSR = 40,
		DREG_ORIG_EAX = 41,
		DREG_NUM_LINUX_I386,
		DREG_YMM0H,
		DREG_YMM7H = DREG_YMM0H + 7,
	};

	/**
	 * Return the total number of registers for this target.
	 */
	size_t total_registers() const { return DREG_NUM_LINUX_I386; }

	/**
	 * Write the value for register |regno| into |buf|, which should
	 * be large enough to hold any register supported by the target.
	 * Return the number of bytes written, 0 to indicate that the
	 * register is unavailable.
	 */
	size_t read_register(uint8_t* buf, unsigned int regno) const;
};
#endif /* RR_REGISTERS_H_ */
