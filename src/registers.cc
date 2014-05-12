/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

//#define DEBUGTAG "registers"

#include "registers.h"

#include <string.h>

template<typename T>
static size_t copy_register_value(uint8_t* buf, T src)
{
	memcpy(buf, &src, sizeof(src));
	return sizeof(src);
}

size_t Registers::read_register(uint8_t* buf, unsigned int regno) const
{
	switch (regno) {
	case DREG_EAX:
		return copy_register_value(buf, eax);
	case DREG_ECX:
		return copy_register_value(buf, ecx);
	case DREG_EDX:
		return copy_register_value(buf, edx);
	case DREG_EBX:
		return copy_register_value(buf, edx);
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
	case DREG_ORIG_EAX:
		return copy_register_value(buf, orig_eax);
	default:
		return 0;
  }
}

