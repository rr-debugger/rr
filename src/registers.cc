/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

//#define DEBUGTAG "registers"

#include "registers.h"

#include <assert.h>
#include <string.h>

void Registers::print_register_file(FILE* f) const
{
	fprintf(f, "Printing register file:\n");
	fprintf(f, "eax: %lx\n", eax);
	fprintf(f, "ebx: %lx\n", ebx);
	fprintf(f, "ecx: %lx\n", ecx);
	fprintf(f, "edx: %lx\n", edx);
	fprintf(f, "esi: %lx\n", esi);
	fprintf(f, "edi: %lx\n", edi);
	fprintf(f, "ebp: %lx\n", ebp);
	fprintf(f, "esp: %lx\n", esp);
	fprintf(f, "eip: %lx\n", eip);
	fprintf(f, "eflags %lx\n",eflags);
	fprintf(f, "orig_eax %lx\n", orig_eax);
	fprintf(f, "xcs: %lx\n", xcs);
	fprintf(f, "xds: %lx\n", xds);
	fprintf(f, "xes: %lx\n", xes);
	fprintf(f, "xfs: %lx\n", xfs);
	fprintf(f, "xgs: %lx\n", xgs);
	fprintf(f, "xss: %lx\n", xss);
	fprintf(f, "\n");
}

void Registers::print_register_file_compact(FILE* f) const
{
	fprintf(f, "eax:%lx ebx:%lx ecx:%lx edx:%lx esi:%lx edi:%lx ebp:%lx esp:%lx eip:%lx eflags:%lx",
		eax, ebx, ecx, edx, esi, edi, ebp, esp, eip, eflags);
}

void Registers::print_register_file_for_trace(FILE* f, bool raw_dump) const
{
	if (raw_dump) {
		fprintf(f,
			" %ld %ld %ld %ld %ld %ld %ld"
			" %ld %ld %ld %ld",
			eax, ebx, ecx, edx, esi, edi, ebp,
			orig_eax, esp, eip, eflags);
	} else {
		fprintf(f,
"  eax:0x%lx ebx:0x%lx ecx:0x%lx edx:0x%lx esi:0x%lx edi:0x%lx ebp:0x%lx\n"
"  eip:0x%lx esp:0x%lx eflags:0x%lx orig_eax:%ld xfs:0x%lx xgs:0x%lx\n",
			eax, ebx, ecx, edx, esi, edi, ebp,
			eip, esp, eflags, orig_eax, xfs, xgs);
	}
}

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

