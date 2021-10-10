#ifndef __RR_RTLD_AUDIT_H__
#define __RR_RTLD_AUDIT_H__

#include <stdbool.h>
#include <inttypes.h>
#include <elf.h>

#define PRIxELFADDR _PRIxELFADDR(PRIx, __ELF_NATIVE_CLASS)
#define _PRIxELFADDR(f, w) _PRIxELFADDR_1(f, w)
#define _PRIxELFADDR_1(f, w) f##w

extern bool rr_audit_debug;

#endif
