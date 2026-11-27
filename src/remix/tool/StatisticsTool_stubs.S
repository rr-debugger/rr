        .set StatsRecord_effective_address_low_byte_frequences, 0

        .text
        .p2align 4

#define BEGIN_FUNCTION(fun) \
        .global fun; \
        .type fun, @function; \
fun: \
        .cfi_startproc

#define END_FUNCTION(fun) \
        .cfi_endproc; \
        .size fun, . - fun


/* On entry, %r11 holds our return address. Trashes %r8, %r9 and %r10. */
        BEGIN_FUNCTION(before_xgetbv_stub)
        mov %rsp,%r10
        mov saved_rsp(%rip),%rsp
        call prepare_enter_cpp_fast
        /* Pushing 8 bytes aligns the stack. We also need to save and restore
           %r11 since C++ will trash it. */
        push %r11
        call before_xgetbv
        pop %r11
        call prepare_exit_cpp_fast
        mov %r10,%rsp
        jmp *%r11
        END_FUNCTION(before_xgetbv_stub)


/* On entry, %r11 holds our return address and %r8 contains the effective address
   of a memory operand. Trashes %r8 and %r9. */
        BEGIN_FUNCTION(mem_operand_stub)
        mov stats_record(%rip),%r9
        movzx %r8b,%r8d
        lea StatsRecord_effective_address_low_byte_frequences(%r9,%r8,8),%r8
        mov (%r8),%r9
        lea 1(%r9),%r9
        mov %r9,(%r8)
        jmp *%r11
        END_FUNCTION(mem_operand_stub)
