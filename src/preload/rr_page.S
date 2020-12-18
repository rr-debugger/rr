// # Layout of the librrpage.so file
//
// The `rr page` is a special page mapped in low memory (at RR_PAGE_ADDR) that
// contains syscall instructions at known ip values. These values must be fixed
// for all processes in a given rr session, since rr cannot adjust the seccomp
// filter that makes use of these values once it has been set. `librrpage.so`
// contains this page, and rr will attmept to have the dynamic linker map it
// such that the dynamic-linker-loaded copy of the rr page will be at the same
// address as the copy unconditionally loaded by rr such that debuggers and
// internal unwinders don't get confused by the presence of a random code page.
// Should the mapping not succeed for whatever reason, rr will still use its
// internal copy of the rr page.
//
// The `librrpage.so` file is made up of three pages:
// 1: The ELF header, symbol/string table, and eh_frame sections
// 2: The rr page to be used during recording
// 3: The rr page to be used during replay
//
// librrpage.so itself is set up to request the dynamic linker to only map the
// first two pages. During replay, rr will map the third page in place of the
// second. Note however, that we only have one copy of the eh_frame and symbol
// information - we expect all offsets and unwind instructions to match between
// the record and replay versions (anything else would likely result in
// divergences anyway)

#ifdef __i386__
#define CALL \
    int $0x80; \
    ret
#define NOCALL \
    xor %eax, %eax; \
    ret
#define TRAP \
    int $3; \
    ret
#elif defined(__x86_64__)
#define CALL \
    syscall; \
    ret
#define NOCALL \
    xor %eax, %eax; \
    ret
#define TRAP \
    nop; int $3; \
    ret
#elif defined(__aarch64__)
#define CALL \
    svc #0; \
    ret
#define NOCALL \
    movz x0, #0; \
    ret
#define TRAP \
    brk #0; \
    ret
#endif

.section .vdso.text, "a", @progbits
.align 0x1000

#include "rr_vdso.S"

.section .record.text, "a", @progbits
.align 0x1000

.global rr_page_start
rr_page_start:

#define STARTPROC(name) #name:; .cfi_startproc
#define STARTPROC_GLOBAL(name) .global #name; #name:; .cfi_startproc
#define CFI_ENDPROC .cfi_endproc
#include "rr_page_instructions.S"

.section .replay.text, "", @progbits
.align 0x1000
replay_page:
// No CFI instructions or symbols for the replay page - we'll implicitly share
// those of the record copy
#undef STARTPROC
#undef CFI_ENDPROC
#define STARTPROC(name)
#define CFI_ENDPROC
#define IS_REPLAY 1
#include "rr_page_instructions.S"
