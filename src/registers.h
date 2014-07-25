/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef RR_REGISTERS_H_
#define RR_REGISTERS_H_

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/user.h>

#include <vector>

#include "types.h"

/**
 * A Registers object contains values for all general-purpose registers.
 * These must include all registers used to pass syscall parameters and return
 * syscall results.
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
	supported_arch arch() const { return x86; }

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

	/**
	 * Set the register containing syscall argument |Index| to
	 * |value|.
	 */
	template<int Index, typename T>
	void set_arg(T value) { set_arg<Index>(uintptr_t(value)); }

	template<int Index>
	void set_arg(uintptr_t value)
	{
		static_assert(1 <= Index && Index <= 6,
			      "Index must be in range");
		switch (Index) {
		case 1: return set_arg1(value);
		case 2: return set_arg2(value);
		case 3: return set_arg3(value);
		case 4: return set_arg4(value);
		case 5: return set_arg5(value);
		case 6: return set_arg6(value);
		}
	}

	void print_register_file(FILE* f) const;
	void print_register_file_compact(FILE* f) const;
	void print_register_file_for_trace(FILE*, bool raw_dump) const;

	/**
	 * Return true if |reg1| matches |reg2|.  If |mismatch_behavior|
	 * is BAIL_ON_MISMATCH, mismatched registers will be logged as
	 * errors; if |mismatch_behavior| is LOG_MISMATCHES, mismatched
	 * registers will be logged as informative messages.
	 */
	static bool compare_register_files(const char* name1,
					   const Registers* reg1,
					   const char* name2,
					   const Registers* reg2,
					   int mismatch_behavior);

	// Various things the GDB stub needs to know about.
	enum DebuggerRegister {
		DREG_EAX, DREG_ECX, DREG_EDX, DREG_EBX,
		DREG_ESP, DREG_EBP, DREG_ESI, DREG_EDI,
		DREG_EIP, DREG_EFLAGS,
		DREG_CS, DREG_SS, DREG_DS, DREG_ES, DREG_FS, DREG_GS,
		/* We can't actually fetch the floating-point-related
		 * registers, but we record them here so we can
		 * communicate their sizes accurately.
		 */
		DREG_ST0, DREG_ST1, DREG_ST2, DREG_ST3,
		DREG_ST4, DREG_ST5, DREG_ST6, DREG_ST7,
		/* These are the names GDB gives the registers.  */
		DREG_FCTRL, DREG_FSTAT, DREG_FTAG, DREG_FISEG,
		DREG_FIOFF, DREG_FOSEG, DREG_FOOFF, DREG_FOP,
		DREG_XMM0, DREG_XMM1, DREG_XMM2, DREG_XMM3,
		DREG_XMM4, DREG_XMM5, DREG_XMM6, DREG_XMM7,
		DREG_MXCSR,
		DREG_ORIG_EAX,
		DREG_NUM_LINUX_I386,
		DREG_YMM0H, DREG_YMM1H, DREG_YMM2H, DREG_YMM3H,
		DREG_YMM4H, DREG_YMM5H, DREG_YMM6H, DREG_YMM7H,
		/* Last register we can find in user_regs_struct (except for
		 * orig_eax). */
		DREG_NUM_USER_REGS = DREG_GS + 1,
	};

	/**
	 * Return the total number of registers for this target.
	 */
	size_t total_registers() const { return DREG_NUM_LINUX_I386; }

	// TODO: refactor me to use the DbgRegister helper from
	// debugger_gdb.h.

	/**
	 * Write the value for register |regno| into |buf|, which should
	 * be large enough to hold any register supported by the target.
	 * Return the size of the register in bytes and set |defined| to
	 * indicate whether a useful value has been written to |buf|.
	 */
	size_t read_register(uint8_t* buf, unsigned int regno,
			     bool* defined) const;

	/**
	 * Update the registe named |reg_name| to |value| with
	 * |value_size| number of bytes.
	 */
	void write_register(unsigned reg_name,
			    const uint8_t* value, size_t value_size);
};

/**
 * An ExtraRegisters object contains values for all user-space-visible
 * registers other than those in Registers.
 *
 * Task is responsible for creating meaningful values of this class.
 *
 * On x86, the data is an XSAVE area.
 */
class ExtraRegisters {
public:
	// Create empty (uninitialized/unknown registers) value
	ExtraRegisters() {}

	// Set values from raw data
	void set_to_raw_data(std::vector<byte>& consume_data)
	{
		std::swap(data, consume_data);
	}
	int data_size() const { return data.size(); }
	const byte* data_bytes() const { return data.data(); }
	bool empty() const { return data.empty(); }

private:
	friend class Task;

	std::vector<byte> data;
};

#endif /* RR_REGISTERS_H_ */
