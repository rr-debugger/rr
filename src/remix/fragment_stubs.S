#include "fragment_stubs.h"

        .set user_regs_struct_r15, 0
        .set user_regs_struct_r14, 8
        .set user_regs_struct_r13, 16
        .set user_regs_struct_r12, 24
        .set user_regs_struct_rbp, 32
        .set user_regs_struct_rbx, 40
        .set user_regs_struct_r11, 48
        .set user_regs_struct_r10, 56
        .set user_regs_struct_r9, 64
        .set user_regs_struct_r8, 72
        .set user_regs_struct_rax, 80
        .set user_regs_struct_rcx, 88
        .set user_regs_struct_rdx, 96
        .set user_regs_struct_rsi, 104
        .set user_regs_struct_rdi, 112
        .set user_regs_struct_orig_rax, 120
        .set user_regs_struct_rip, 128
        .set user_regs_struct_cs, 136
        .set user_regs_struct_eflags, 144
        .set user_regs_struct_rsp, 152
        .set user_regs_struct_ss, 160
        .set user_regs_struct_fs_base, 168
        .set user_regs_struct_gs_base, 176
        .set user_regs_struct_ds, 184
        .set user_regs_struct_es, 192
        .set user_regs_struct_fs, 200
        .set user_regs_struct_gs, 208

        .set SYS_mprotect, 10

        .set Translation_pc, 0
        .set Translation_translation, 8
        .set Translation_next_by_pc, 16
        .set Translation_is_visited_pc, 24

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

/* Save RAX to R11 and flags to RAX */
#define SAVE_FLAGS() \
        mov %rax,%r11; \
        lahf; \
        seto %al

#define RESTORE_FLAGS() \
        add $0x7f,%al; \
        sahf; \
        mov %r11,%rax

        BEGIN_FUNCTION(run_fragment)
        /* Save all callee-saves registers */
        push %rbp
        push %rbx
        push %r12
        push %r13
        push %r14
        push %r15
        /* Restore application registers */
        mov %rdi,%r8
        call prepare_exit_cpp
        mov %rsp,saved_rsp(%rip)
        mov %r10,%rsp
        jmp *%r8
        END_FUNCTION(run_fragment)


        BEGIN_FUNCTION(return_from_run_fragment)
        mov %rsp,%r10
        mov saved_rsp(%rip),%rsp
        call prepare_enter_cpp
        /* Restore callee-saves registers */
        pop %r15
        pop %r14
        pop %r13
        pop %r12
        pop %rbx
        pop %rbp
        ret
        END_FUNCTION(return_from_run_fragment)


        /* On entry, %r8 contains the current pc */
        BEGIN_FUNCTION(breakpoint_stop_stub)
        mov %r8,(remix_registers + user_regs_struct_rip)(%rip)
        movb $1,stop_flag(%rip)
        movb $1,breakpoint_flag(%rip)
        jmp return_from_run_fragment
        END_FUNCTION(breakpoint_stop_stub)


        /* On entry, %r8 contains the next pc */
        BEGIN_FUNCTION(sync_signal_stop_stub)
        mov %r8,(remix_registers + user_regs_struct_rip)(%rip)
        movb $1,stop_flag(%rip)
        movb $1,sync_signal_flag(%rip)
        jmp return_from_run_fragment
        END_FUNCTION(sync_signal_stop_stub)


        BEGIN_FUNCTION(unconditional_stop_stub)
        mov stop_pc(%rip),%r8
        mov %r8,(remix_registers + user_regs_struct_rip)(%rip)
        movb $1,stop_flag(%rip)
        jmp return_from_run_fragment
        END_FUNCTION(unconditional_stop_stub)


        /* On entry: app %rsp saved to %r10, %rsp set to saved_rsp.
           The C/C++ code entered will see correct GP-register state in
           remix_registers.
           %r8,%r9,%r11 preserved, %r10 destroyed. */
        BEGIN_FUNCTION(prepare_enter_cpp)
        mov %r10,(remix_registers + user_regs_struct_rsp)(%rip)
        lea remix_registers(%rip),%r10
        mov %r15,user_regs_struct_r15(%r10)
        mov %r14,user_regs_struct_r14(%r10)
        mov %r13,user_regs_struct_r13(%r10)
        mov %r12,user_regs_struct_r12(%r10)
        mov %rbp,user_regs_struct_rbp(%r10)
        mov %rbx,user_regs_struct_rbx(%r10)
        mov %rax,user_regs_struct_rax(%r10)
        mov %rcx,user_regs_struct_rcx(%r10)
        mov %rdx,user_regs_struct_rdx(%r10)
        mov %rsi,user_regs_struct_rsi(%r10)
        mov %rdi,user_regs_struct_rdi(%r10)
        pushf
        pop %r10
        mov %r10,(remix_registers + user_regs_struct_eflags)(%rip)

        /* C code expects DF to be clear */
        cld

        movb $0,in_generated_code(%rip)
        /* Fall through */
        END_FUNCTION(prepare_enter_cpp)


        BEGIN_FUNCTION(save_xmm_state)
        vstmxcsr saved_mxcsr(%rip)
        vldmxcsr reference_mxcsr(%rip)
        movdqa %xmm0,(saved_mm_regs + 0*16)(%rip)
        movdqa %xmm1,(saved_mm_regs + 1*16)(%rip)
        movdqa %xmm2,(saved_mm_regs + 2*16)(%rip)
        movdqa %xmm3,(saved_mm_regs + 3*16)(%rip)
        movdqa %xmm4,(saved_mm_regs + 4*16)(%rip)
        movdqa %xmm5,(saved_mm_regs + 5*16)(%rip)
        movdqa %xmm6,(saved_mm_regs + 6*16)(%rip)
        movdqa %xmm7,(saved_mm_regs + 7*16)(%rip)
        movdqa %xmm8,(saved_mm_regs + 8*16)(%rip)
        movdqa %xmm9,(saved_mm_regs + 9*16)(%rip)
        movdqa %xmm10,(saved_mm_regs + 10*16)(%rip)
        movdqa %xmm11,(saved_mm_regs + 11*16)(%rip)
        movdqa %xmm12,(saved_mm_regs + 12*16)(%rip)
        movdqa %xmm13,(saved_mm_regs + 13*16)(%rip)
        movdqa %xmm14,(saved_mm_regs + 14*16)(%rip)
        movdqa %xmm15,(saved_mm_regs + 15*16)(%rip)
        ret
        END_FUNCTION(save_xmm_state)


        /* On exit: app %rsp in %r10. Trashes %r9. Preserves %r8 and %r11.
           All non-scratch registers are replaced with their application values. */
        BEGIN_FUNCTION(prepare_exit_cpp)
        lea remix_registers(%rip),%r9
        mov user_regs_struct_r15(%r9),%r15
        mov user_regs_struct_r14(%r9),%r14
        mov user_regs_struct_r13(%r9),%r13
        mov user_regs_struct_r12(%r9),%r12
        mov user_regs_struct_rbp(%r9),%rbp
        mov user_regs_struct_rbx(%r9),%rbx
        mov user_regs_struct_rax(%r9),%rax
        mov user_regs_struct_rcx(%r9),%rcx
        mov user_regs_struct_rdx(%r9),%rdx
        mov user_regs_struct_rsi(%r9),%rsi
        mov user_regs_struct_rdi(%r9),%rdi
        push user_regs_struct_eflags(%r9)
        popf
        mov user_regs_struct_rsp(%r9),%r10
        movb $1,in_generated_code(%rip)
        /* Fall through */
        END_FUNCTION(prepare_exit_cpp)


        BEGIN_FUNCTION(restore_xmm_state)
        movdqa (saved_mm_regs + 0*16)(%rip),%xmm0
        movdqa (saved_mm_regs + 1*16)(%rip),%xmm1
        movdqa (saved_mm_regs + 2*16)(%rip),%xmm2
        movdqa (saved_mm_regs + 3*16)(%rip),%xmm3
        movdqa (saved_mm_regs + 4*16)(%rip),%xmm4
        movdqa (saved_mm_regs + 5*16)(%rip),%xmm5
        movdqa (saved_mm_regs + 6*16)(%rip),%xmm6
        movdqa (saved_mm_regs + 7*16)(%rip),%xmm7
        movdqa (saved_mm_regs + 8*16)(%rip),%xmm8
        movdqa (saved_mm_regs + 9*16)(%rip),%xmm9
        movdqa (saved_mm_regs + 10*16)(%rip),%xmm10
        movdqa (saved_mm_regs + 11*16)(%rip),%xmm11
        movdqa (saved_mm_regs + 12*16)(%rip),%xmm12
        movdqa (saved_mm_regs + 13*16)(%rip),%xmm13
        movdqa (saved_mm_regs + 14*16)(%rip),%xmm14
        movdqa (saved_mm_regs + 15*16)(%rip),%xmm15
        vldmxcsr saved_mxcsr(%rip)
        movl $0,saved_mxcsr(%rip)
        ret
        END_FUNCTION(restore_xmm_state)


        /* On entry: app %rsp saved to %r10, %rsp set to saved_rsp.
           The C/C++ code entered will ONLY see correct GP-register state in
           remix_registers for %rsp,%eflags,%rax,%rcx,%rdx,%rsi,%rdi.
           It is NOT allowed to use MM or x87 registers since they are not
           being saved/restored.
           %r8,%r9,%r11 preserved, %r10 destroyed. */
        BEGIN_FUNCTION(prepare_enter_cpp_fast)
        mov %r10,(remix_registers + user_regs_struct_rsp)(%rip)
        lea remix_registers(%rip),%r10
        pushf
        pop user_regs_struct_eflags(%r10)
        mov %rax,user_regs_struct_rax(%r10)
        mov %rcx,user_regs_struct_rcx(%r10)
        mov %rdx,user_regs_struct_rdx(%r10)
        mov %rsi,user_regs_struct_rsi(%r10)
        mov %rdi,user_regs_struct_rdi(%r10)
        /* C code expects DF to be clear */
        cld
        movb $0,in_generated_code(%rip)
        ret
        END_FUNCTION(prepare_enter_cpp_fast)


        /* On exit: app %rsp in %r10. Preserves %r8,%r9,%r11. */
        BEGIN_FUNCTION(prepare_exit_cpp_fast)
        lea remix_registers(%rip),%r10
        mov user_regs_struct_rax(%r10),%rax
        mov user_regs_struct_rcx(%r10),%rcx
        mov user_regs_struct_rdx(%r10),%rdx
        mov user_regs_struct_rsi(%r10),%rsi
        mov user_regs_struct_rdi(%r10),%rdi
        mov user_regs_struct_eflags(%r10),%r10
        push %r10
        popf
        mov (remix_registers + user_regs_struct_rsp)(%rip),%r10
        movb $1,in_generated_code(%rip)
        ret
        END_FUNCTION(prepare_exit_cpp_fast)


        /* On entry, return address is in %r8. Called only when pc ==
         * stop_pc. */
        BEGIN_FUNCTION(conditional_stop_stub)
        /* Check the RCB counter first. The common case is that it hasn't
           reached the target yet, so make that fast. */
        SAVE_FLAGS()
        mov remix_rcb(%rip),%r9
        cmp remix_target_rcb(%rip),%r9
        jge 1f
        /* Fast path: haven't reached RCB target yet */
        RESTORE_FLAGS()
        jmp *%r8
1:
        RESTORE_FLAGS()
        /* Update remix_registers.rip before we call match_registers, which
           checks it. */
        mov stop_pc(%rip),%r9
        mov %r9,(remix_registers + user_regs_struct_rip)(%rip)
        mov %rsp,%r10
        mov saved_rsp(%rip),%rsp
        call prepare_enter_cpp
        mov %r8,%r13
        /* Align stack */
        push %rax
        call match_registers
        mov %r13,%r8
        test %eax,%eax
        jne 2f
        /* No match, so restore state and jump to %r8 to continue */
        call prepare_exit_cpp
        mov %r10,%rsp
        jmp *%r8
2:
        /* Match, so restore state and return from run_fragment */
        call prepare_exit_cpp
        mov %r10,%rsp
        movb $1,stop_flag(%rip)
        jmp return_from_run_fragment
        END_FUNCTION(conditional_stop_stub)


        /* On entry, return address is in %r8 and stopping PC is in %r9. */
        BEGIN_FUNCTION(conditional_syscall_stop_stub)
        SAVE_FLAGS()
        mov stop_mode(%rip),%r10b
        cmp $1,%r10b
        je 1f
        /* Fast path: not stopping at syscalls */
        RESTORE_FLAGS()
        jmp *%r8
1:
        RESTORE_FLAGS()
        mov %r9,(remix_registers + user_regs_struct_rip)(%rip)
        movb $1,stop_flag(%rip)
        jmp return_from_run_fragment
        END_FUNCTION(conditional_syscall_stop_stub)


        BEGIN_FUNCTION(conditional_breakpoint_fault_stop_stub)
        SAVE_FLAGS()
        test %rsi,%rsi
        jle 1f
        /* Fast path: no need to stop at the syscallbuf break instruction */
        RESTORE_FLAGS()
        jmp *%r8
1:
        RESTORE_FLAGS()
        mov stop_pc(%rip),%r9
        mov %r9,(remix_registers + user_regs_struct_rip)(%rip)
        movb $1,stop_flag(%rip)
        jmp return_from_run_fragment
        END_FUNCTION(conditional_breakpoint_fault_stop_stub)


        /* On entry, return address is in %r8. %r9 is 0 if this is a 64-bit
           syscall, 1 if it's a 32-bit syscall. remix_registers.orig_rax holds
           the syscall number. */
        BEGIN_FUNCTION(monitor_syscall_before_stub)
        mov %rsp,%r10
        mov saved_rsp(%rip),%rsp
        call prepare_enter_cpp
        /* Push 8 bytes aligns stack */
        push %r8
        mov %r9,%rdi
        mov %r8,%rsi
        call before_monitored_syscall
        pop %r8
        call prepare_exit_cpp
        mov %r10,%rsp
        jmp *%r8
        END_FUNCTION(monitor_syscall_before_stub)


        /* On entry, return address is in %r8. %r9 is 0 if this is a 64-bit
           syscall, 1 if it's a 32-bit syscall. remix_registers.orig_rax holds
           the syscall number. THIS CAN INVALIDATE THE CURRENT FRAGMENT
           or its next fragment... */
        BEGIN_FUNCTION(monitor_syscall_stub)
        mov %rsp,%r10
        mov saved_rsp(%rip),%rsp
        call prepare_enter_cpp
        /* Push 8 bytes aligns stack */
        push %r8
        mov %r9,%rdi
        call monitored_syscall
        pop %r8
        test %rax,%rax
        cmovnz %rax,%r8
        call prepare_exit_cpp
        mov %r10,%rsp
        /* We don't want to keep orig_rax changed */
        movq $-1,(remix_registers + user_regs_struct_orig_rax)(%rip)
        jmp *%r8
        END_FUNCTION(monitor_syscall_stub)


        /* On entry, %r8 is the pc of an invalid fragment that we've entered.
           Return from run_fragment . */
        BEGIN_FUNCTION(fixup_invalid_fragment_stub)
        mov %r8,(remix_registers + user_regs_struct_rip)(%rip)
        lea patch_invalid_fragment_stub(%rip),%r8
        mov %r8,patch_callback(%rip)
        jmp return_from_run_fragment
        END_FUNCTION(fixup_invalid_fragment_stub)


        BEGIN_FUNCTION(new_conditional_branch_not_taken_stub)
        /* We do NOT set user_regs_struct_rip here, so it's invalid when
           we return. That's OK, Generator::complete_fragment() will fix it up.
         */
        movb $0,conditional_branch_taken(%rip)
        jmp return_from_run_fragment
        END_FUNCTION(new_conditional_branch_not_taken_stub)


        BEGIN_FUNCTION(new_conditional_branch_taken_stub)
        /* We do NOT set user_regs_struct_rip here, so it's invalid when
           we return. That's OK, Generator::complete_fragment() will fix it up.
         */
        movb $1,conditional_branch_taken(%rip)
        jmp return_from_run_fragment
        END_FUNCTION(new_conditional_branch_taken_stub)


        /* On entry, %r8 is the new pc and %r9 is a pointer to a 4-byte
           pc-relative jump offset that should be patched to point to the
           translated code. */
        BEGIN_FUNCTION(untranslated_branch_stub)
        mov %r8,(remix_registers + user_regs_struct_rip)(%rip)
        lea patch_untranslated_branch(%rip),%r8
        mov %r8,patch_callback(%rip)
        mov %r9,untranslated_branch_offset(%rip)
        jmp return_from_run_fragment
        END_FUNCTION(untranslated_branch_stub)


        /* On entry, %r8 is the return pc, %r9 is the application RSP, and
           %rsp is the return_address_rsp after pushing the translated
           return address. %r11 is the callee translated address.
           Transfers control to that callee entry point with all scratch
           registers trashed.
        */
        BEGIN_FUNCTION(call_stub)
        /* Make room for the app_pc return address. */
        lea -8(%rsp),%rsp
        /* Implement circular return_address_stack by wrapping around
           if necessary. */
        lea return_address_stack(%rip),%r10
        mov %spl,%r10b
        mov %r10,return_address_rsp(%rip)
        /* Save app_pc return address */
        mov %r8,(%r10)
        mov %r9,%rsp
        jmp *%r11
        END_FUNCTION(call_stub)


        /* On entry, %r11 is the return address. On exit, %r8-%r10 are
           trashed. */
        BEGIN_FUNCTION(flush_pending_fip_stub)
        mov %rsp,%r10
        mov saved_rsp(%rip),%rsp
        call prepare_enter_cpp_fast
        /* Pushing 8 bytes aligns the stack */
        push %r11
        call flush_pending_fip
        pop %r11
        call prepare_exit_cpp_fast
        mov %r10,%rsp
        jmp *%r11
        END_FUNCTION(flush_pending_fip_stub)


        /* On entry, %r10 is the return address. On exit, %r9 and %r11 are trashed. */
        BEGIN_FUNCTION(xgetbv_stub)
        jecxz 1f
        /* It's ok to trash %rax here because xgetbv writes to %rax */
        lahf
        seto %al
        mov %rax,%r11
        /* ECX must be 1 here (or else we would have faulted during recording.
           Our current XINUSE bitmap should match the recorded XINUSE bitmap
           so any extra XCR0 bits supported on this host that the recording host
           didn't have should be masked out by XINUSE. */
        xgetbv
        /* On CI we've observed the PKRU bit getting lost under remix sometimes,
           despite being present under rr, so copy the rr behavior of always
           setting the PKRU bit if it's in XCR0. */
        mov (tracee_xcr0)(%rip),%r9d
        andl $0x200,%r9d
        or %r9d,%eax
        xchg %r11,%rax
        add $0x7f,%al
        sahf
        xchg %r11,%rax
        jmp *%r10
1:
        mov tracee_xcr0(%rip),%eax
        mov (tracee_xcr0 + 4)(%rip),%edx
        jmp *%r10
        END_FUNCTION(xgetbv_stub)


        /* On entry, return address is in %r11. The address of the tracee XSAVE
         * region is in %r8. %r9 contains the xsave family instruction opcode.
         * %r10 is destroyed.
         */
        BEGIN_FUNCTION(handle_xsave_stub)
        mov %rsp,%r10
        mov saved_rsp(%rip),%rsp
        call prepare_enter_cpp_fast
        /* Push 8 bytes aligns stack */
        push %r11
        mov %r9, %rdi
        mov %r8, %rsi
        call handle_xsave
        pop %r11
        call prepare_exit_cpp_fast
        mov %r10,%rsp
        jmp *%r11
        END_FUNCTION(handle_xsave_stub)

        /* On entry, %xmm0 is the value to correct, %r8 is the emulation table to use,
           %r10 is the return address.
           saved_mm_regs+32 has the input value.
           On exit, %r9 and %r11 are trashed and %xmm0 is the result.
         */
        BEGIN_FUNCTION(correct_single_rcp_rsqrt_stub)
        SAVE_FLAGS()
        movdqa %xmm4,(saved_mm_regs + 4*16)(%rip)
        mov (saved_mm_regs + 32)(%rip),%r9d
        shr $11,%r9d
        movzxb (22*4)(%r8,%r9,1),%r9d
        /* this clears the high bits of XMM4 */
        movss (%r8,%r9,4),%xmm4
        xorps %xmm4,%xmm0
        movdqa (saved_mm_regs + 4*16)(%rip),%xmm4
        RESTORE_FLAGS()
        jmp *%r10
        END_FUNCTION(correct_single_rcp_rsqrt_stub)


        /* Builds an XOR correction at saved_mm_reg + 64 */
#define CORRECT_PACKED_RCP_RSQRT_LANE(offset)          \
        mov (saved_mm_regs + 32 + offset)(%rip),%r9d;  \
        shr $11,%r9d;                                  \
        movzxb (22*4)(%r8,%r9,1),%r9d;                 \
        mov (%r8,%r9,4),%r9d;                          \
        mov %r9d,(saved_mm_regs + 64 + offset)(%rip)

        /* On entry, %xmm0 is the value to correct, %r8 is the emulation table to use,
           %r10 is the return address.
           saved_mm_regs+32 has the input value.
           On exit, %r9 and %r11 are trashed and %xmm0 is the result.
         */
        BEGIN_FUNCTION(correct_packed_rcp_rsqrt_stub)
        SAVE_FLAGS()
        CORRECT_PACKED_RCP_RSQRT_LANE(0)
        CORRECT_PACKED_RCP_RSQRT_LANE(4)
        CORRECT_PACKED_RCP_RSQRT_LANE(8)
        CORRECT_PACKED_RCP_RSQRT_LANE(12)
        xorps (saved_mm_regs + 64)(%rip),%xmm0
        RESTORE_FLAGS()
        jmp *%r10
        END_FUNCTION(correct_packed_rcp_rsqrt_stub)


        /* On entry, %xmm0 is the value to correct, %r8 is the emulation table to use,
           %r10 is the return address.
           saved_mm_regs+32 has the input value.
           On exit, %r9 and %r11 are trashed and %xmm0 is the result.
         */
        BEGIN_FUNCTION(correct_single_vex_rcp_rsqrt_stub)
        SAVE_FLAGS()
        movdqa %xmm4,(saved_mm_regs + 4*16)(%rip)
        mov (saved_mm_regs + 32)(%rip),%r9d
        shr $11,%r9d
        movzxb (22*4)(%r8,%r9,1),%r9d
        /* this clears the high bits of XMM4 */
        vmovss (%r8,%r9,4),%xmm4
        vxorps %xmm4,%xmm0,%xmm0
        movdqa (saved_mm_regs + 4*16)(%rip),%xmm4
        RESTORE_FLAGS()
        jmp *%r10
        END_FUNCTION(correct_single_vex_rcp_rsqrt_stub)


        /* On entry, %xmm0 is the value to correct, %r8 is the emulation table to use,
           %r10 is the return address.
           saved_mm_regs+32 has the input value.
           On exit, %r9 and %r11 are trashed and %xmm0 is the result.
         */
        BEGIN_FUNCTION(correct_packed_vex_rcp_rsqrt_stub)
        SAVE_FLAGS()
        CORRECT_PACKED_RCP_RSQRT_LANE(0)
        CORRECT_PACKED_RCP_RSQRT_LANE(4)
        CORRECT_PACKED_RCP_RSQRT_LANE(8)
        CORRECT_PACKED_RCP_RSQRT_LANE(12)
        vxorps (saved_mm_regs + 4*16)(%rip),%xmm0,%xmm0
        RESTORE_FLAGS()
        jmp *%r10
        END_FUNCTION(correct_packed_vex_rcp_rsqrt_stub)


        /* On entry, %ymm0 is the value to correct, %r8 is the emulation table to use,
           %r10 is the return address.
           saved_mm_regs+32 has the input value.
           On exit, %r9 and %r11 are trashed and %ymm0 is the result.
         */
        BEGIN_FUNCTION(correct_packed_ymm_rcp_rsqrt_stub)
        SAVE_FLAGS()
        CORRECT_PACKED_RCP_RSQRT_LANE(0)
        CORRECT_PACKED_RCP_RSQRT_LANE(4)
        CORRECT_PACKED_RCP_RSQRT_LANE(8)
        CORRECT_PACKED_RCP_RSQRT_LANE(12)
        CORRECT_PACKED_RCP_RSQRT_LANE(16)
        CORRECT_PACKED_RCP_RSQRT_LANE(20)
        CORRECT_PACKED_RCP_RSQRT_LANE(24)
        CORRECT_PACKED_RCP_RSQRT_LANE(28)
        vxorps (saved_mm_regs + 4*16)(%rip),%ymm0,%ymm0
        RESTORE_FLAGS()
        jmp *%r10
        END_FUNCTION(correct_packed_ymm_rcp_rsqrt_stub)


        /* On entry, %r10 is the return address. On exit, %r9 and %r11 are trashed. */
        BEGIN_FUNCTION(pushf_stub)
        pushf
        SAVE_FLAGS()
        mov extra_rflags(%rip),%r9
        and $0x40100,%r9d
        or %r9,(%rsp)
        RESTORE_FLAGS()
        jmp *%r10
        END_FUNCTION(pushf_stub)


        /* On entry, %r10 is the return address. On exit, %r9 and %r11 are trashed. */
        BEGIN_FUNCTION(pushf16_stub)
        pushfw
        SAVE_FLAGS()
        mov extra_rflags(%rip),%r9w
        and $0x0100,%r9w
        or %r9w,(%rsp)
        RESTORE_FLAGS()
        jmp *%r10
        END_FUNCTION(pushf_stub)


        /* On entry, %r10 is the return app_pc. */
        BEGIN_FUNCTION(ret_stub)
        SAVE_FLAGS()
        mov return_address_rsp(%rip),%r8
        cmp (%r8),%r10
        lea 8(%r8),%r8
        mov %rsp,%r9
        lea return_address_stack(%rip),%rsp
        mov %r8b,%spl
        lea 8(%rsp),%r8
        mov %r8,return_address_rsp(%rip)
        jne 1f
        RESTORE_FLAGS()
        ret
1:
        mov %r9,%rsp
        /* Fall through to indirect_jump_slow_path */
        END_FUNCTION(ret_stub)


        /* On entry, SAVE_FLAGS() has been done and %r10 is the pc to jump to */
        BEGIN_FUNCTION(indirect_jump_slow_path)
        mov %r10,%r8
        imul $PC_HASH_MULTIPLICAND,%r8
        shr $PC_HASH_SHIFT,%r8
        and $(PC_HASH_SIZE - 1),%r8
        mov pc_hash(%rip),%r9
        mov (%r9,%r8,8),%r8
1:
        test %r8,%r8
        je 3f
        cmp Translation_pc(%r8),%r10
        jne 2f
        /* This is it. Check if we need to bail out instead of jumping
           directly to this translation. */
        mov Translation_is_visited_pc(%r8),%r9b
        test %r9b,%r9b
        jne 4f
        mov Translation_translation(%r8),%r8
        /* Populate the cache */
        mov %r10,%r9
        and $(INDIRECT_JUMP_CACHE_SIZE/8 - 2),%r9
        RESTORE_FLAGS()
        /* Now %r11 is free! */
        mov indirect_jump_cache(%rip),%r11
        lea (%r11,%r9,8),%r9
        mov %r10,(%r9)
        mov %r8,8(%r9)
        jmp *%r8
2:
        mov Translation_next_by_pc(%r8),%r8
        jmp 1b
3:
        lea patch_refill_indirect_jump_cache(%rip),%r8
        mov %r8,patch_callback(%rip)
4:
        mov %r10,(remix_registers + user_regs_struct_rip)(%rip)
        RESTORE_FLAGS()
        jmp return_from_run_fragment
        END_FUNCTION(indirect_jump_slow_path)


        /* indirect_call_stub: On entry, %r10 is the pc to jump to. %r9 is the application RSP.
           %r8 is the app_pc return address. */
        /* indirect_jump_stub: On entry, %r10 is the pc to jump to. */
#define INDIRECT_JUMP_STUB(c, n) \
        BEGIN_FUNCTION(indirect_call_stub_##c##_##n); \
        lea -8(%rsp),%rsp; \
        lea return_address_stack(%rip),%r11; \
        mov %spl,%r11b; \
        mov %r11,return_address_rsp(%rip); \
        mov %r8,(%r11); \
        mov %r9,%rsp; \
        END_FUNCTION(indirect_call_stub_##c##_##n); \
        BEGIN_FUNCTION(indirect_jump_stub_##c##_##n); \
        SAVE_FLAGS(); \
        mov %r10,%r9; \
        and $(INDIRECT_JUMP_CACHE_SIZE/8 - 2),%r9; \
        lea indirect_jump_cache_##c(%rip),%r8; \
        cmp (%r8,%r9,8),%r10; \
        jne 1f; \
        RESTORE_FLAGS(); \
        jmp *8(%r8,%r9,8); \
1: \
        jmp indirect_jump_slow_path; \
        END_FUNCTION(indirect_jump_stub_##c##_##n)

        INDIRECT_JUMP_STUB(0, 0)
        INDIRECT_JUMP_STUB(0, 1)
        INDIRECT_JUMP_STUB(0, 2)
        INDIRECT_JUMP_STUB(0, 3)
        INDIRECT_JUMP_STUB(0, 4)
        INDIRECT_JUMP_STUB(0, 5)
        INDIRECT_JUMP_STUB(0, 6)
        INDIRECT_JUMP_STUB(0, 7)


        INDIRECT_JUMP_STUB(1, 0)
        INDIRECT_JUMP_STUB(1, 1)
        INDIRECT_JUMP_STUB(1, 2)
        INDIRECT_JUMP_STUB(1, 3)
        INDIRECT_JUMP_STUB(1, 4)
        INDIRECT_JUMP_STUB(1, 5)
        INDIRECT_JUMP_STUB(1, 6)
        INDIRECT_JUMP_STUB(1, 7)


        /* On entry, %r10 is the pc to jump to */
        BEGIN_FUNCTION(singlestep_indirect_jump_stub)
        mov %r10,(remix_registers + user_regs_struct_rip)(%rip)
        jmp return_from_run_fragment
        END_FUNCTION(singlestep_indirect_jump_stub)


        /* On entry, %r8 is the next pc */
        BEGIN_FUNCTION(directed_return_stub)
        mov %r8,(remix_registers + user_regs_struct_rip)(%rip)
        jmp return_from_run_fragment
        END_FUNCTION(directed_return_stub)


        /* SIGSEGV in a WX page is routed here by setting the PC to this
           address and filling in remix_sighandler_state. */
        BEGIN_FUNCTION(remix_wx_sighandler)
        movb $0,in_generated_code(%rip)
        mov %rsp,sighandler_saved_rsp(%rip)
        mov saved_rsp(%rip),%rsp
        pushf
        push %rax
        push %rcx
        push %rdx
        push %rsi
        push %rdi
        push %r8
        push %r9
        push %r10
        push %r11
        /* C code expects DF to be clear */
        cld
        /* Align stack */
        sub $8,%rsp
        call wx_sighandler_internal
        add $8,%rsp
        pop %r11
        pop %r10
        pop %r9
        pop %r8
        pop %rdi
        pop %rsi
        pop %rdx
        pop %rcx
        pop %rax
        popf
        mov sighandler_saved_rsp(%rip),%rsp
        movb $1,in_generated_code(%rip)
        jmp *remix_sighandler_state(%rip)
        END_FUNCTION(remix_wx_sighandler)


        /* Returns from run_fragment, abandoning the current state. */
        BEGIN_FUNCTION(return_from_run_fragment_no_save_state)
        movb $0,in_generated_code(%rip)
        vldmxcsr reference_mxcsr(%rip)
        cld
        mov saved_rsp(%rip),%rsp
        /* Restore callee-saves registers */
        pop %r15
        pop %r14
        pop %r13
        pop %r12
        pop %rbx
        pop %rbp
        ret
        END_FUNCTION(return_from_run_fragment_no_save_state)
