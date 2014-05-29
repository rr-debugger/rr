/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

//#define DEBUGTAG "registers"

#include "registers.h"

#include <assert.h>
#include <string.h>

template<typename T>
static size_t copy_register_value(uint8_t* buf, T src)
{
	memcpy(buf, &src, sizeof(src));
	return sizeof(src);
}

size_t Registers::read_register(uint8_t* buf, unsigned int regno,
				bool* defined) const
{
	*defined = true;
	assert(regno < total_registers());
	switch (regno) {
	case DREG_EAX:
		return copy_register_value(buf, eax);
	case DREG_ECX:
		return copy_register_value(buf, ecx);
	case DREG_EDX:
		return copy_register_value(buf, edx);
	case DREG_EBX:
		return copy_register_value(buf, ebx);
	case DREG_ESP:
		return copy_register_value(buf, esp);
	case DREG_EBP:
		return copy_register_value(buf, ebp);
	case DREG_ESI:
		return copy_register_value(buf, esi);
	case DREG_EDI:
		return copy_register_value(buf, edi);
	case DREG_EIP:
		return copy_register_value(buf, eip);
	case DREG_EFLAGS:
		return copy_register_value(buf, eflags);
	case DREG_CS:
		return copy_register_value(buf, xcs);
	case DREG_SS:
		return copy_register_value(buf, xss);
	case DREG_DS:
		return copy_register_value(buf, xds);
	case DREG_ES:
		return copy_register_value(buf, xes);
	case DREG_FS:
		return copy_register_value(buf, xfs);
	case DREG_GS:
		return copy_register_value(buf, xgs);
	case DREG_ST0:
	case DREG_ST1:
	case DREG_ST2:
	case DREG_ST3:
	case DREG_ST4:
	case DREG_ST5:
	case DREG_ST6:
	case DREG_ST7:
		*defined = false;
		/* Yes, really.  If somehow we ever support x87 values in
		 * the debugger, we will have to be careful about how we
		 * format our bits here.
		 */
		return 10;
	case DREG_FCTRL:
	case DREG_FSTAT:
	case DREG_FTAG:
	case DREG_FISEG:
	case DREG_FOSEG:
	case DREG_FOP:
		*defined = false;
		return 2;
	case DREG_FIOFF:
	case DREG_FOOFF:
		*defined = false;
		return 4;
	case DREG_ORIG_EAX:
		return copy_register_value(buf, orig_eax);
	case DREG_XMM0:
	case DREG_XMM1:
	case DREG_XMM2:
	case DREG_XMM3:
	case DREG_XMM4:
	case DREG_XMM5:
	case DREG_XMM6:
	case DREG_XMM7:
		*defined = false;
		return 16;
	case DREG_MXCSR:
		*defined = false;
		return 4;
	case DREG_YMM0H:
	case DREG_YMM1H:
	case DREG_YMM2H:
	case DREG_YMM3H:
	case DREG_YMM4H:
	case DREG_YMM5H:
	case DREG_YMM6H:
	case DREG_YMM7H:
		*defined = false;
		return 16;
	default:
		assert(false);
		return 0;
  }
}

