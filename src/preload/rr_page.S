// # Layout of the librrpage.so file
//
// The `rr page` is a special page mapped in low memory (at RR_PAGE_ADDR) that
// contains syscall instructions at known ip values. These values must be fixed
// for all processes in a given rr session, since rr cannot adjust the seccomp
// filter that makes use of these values once it has been set. `librrpage.so`
// contains this page, and rr will map it in place at process start and inform
// the process about it by passing it as the address of the vdso. This way
// the tracee's unwinders, as well as GDB will load the librrpage.so symbols and
// unwind info and function correctly if execution is stopped in these locations.
//
// The `librrpage.so` file is made up of five pages:
// 1: The ELF header, dynamic symbol/string table, and eh_frame sections
// 2: The ELF section, symbol string tables (moved here in a post-processing step)
// 3: A fake vdso that rr will ask the kernel to treat as the real vdso
// 4: The rr page to be used during recording
// 5: The rr page to be used during replay
//
// During record, rr will map the first four pages of librrpage.so only.
// During replay, rr will replace the record page by the replay page.
// Note however, that we only have one copy of the eh_frame and symbol
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
#define PAGE_ALIGN \
    .align 0x1000
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
#define PAGE_ALIGN \
    .align 0x1000
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
#define PAGE_ALIGN \
    .align 12
#endif

.section .sh_placeholder, "a"
PAGE_ALIGN
.fill 0x1000, 1, 0xff

.section .vdso.text, "a", @progbits
PAGE_ALIGN

#include "rr_vdso.S"

.section .record.text, "a", @progbits
PAGE_ALIGN

.global rr_page_start
rr_page_start:

#define STARTPROC(name) #name:; .cfi_startproc
#define STARTPROC_GLOBAL(name) .global #name; #name:; .cfi_startproc
#define CFI_ENDPROC .cfi_endproc
#include "rr_page_instructions.S"

.section .replay.text, "", @progbits
PAGE_ALIGN
replay_page:
// No CFI instructions or symbols for the replay page - we'll implicitly share
// those of the record copy
#undef STARTPROC
#undef CFI_ENDPROC
#define STARTPROC(name)
#define CFI_ENDPROC
#define IS_REPLAY 1
#include "rr_page_instructions.S"
