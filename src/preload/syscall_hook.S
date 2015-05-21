        /* This must match the numbers in X86SyscallStubMonkeypatch and
           X64SyscallStubMonkeypatch */
        .set _syscall_stack_adjust,256

#if defined(__i386__)
/**
 * Jump to this hook from |__kernel_vsyscall()|, to buffer syscalls that
 * we otherwise couldn't wrap through LD_PRELOAD helpers.  Return the
 * *RAW* kernel return value, not the -1/errno mandated by POSIX.
 *
 * Remember, this function runs *below* the level of libc.  libc can't
 * know that its call to |__kernel_vsyscall()| has been re-routed to
 * us.
 */
        .text
        .global _syscall_hook_trampoline
        .hidden _syscall_hook_trampoline
        .type _syscall_hook_trampoline, @function

_syscall_hook_trampoline:
        .cfi_startproc

        /* Build a |struct syscall_info| by pushing all the syscall
         * args and the number onto the stack. */
                          /* struct syscall_info info; */
        pushl %ebp        /* info.args[5] = $ebp; */
        .cfi_adjust_cfa_offset 4
        .cfi_rel_offset %ebp, 0
        pushl %edi        /* info.args[4] = $edi; */
        .cfi_adjust_cfa_offset 4
        .cfi_rel_offset %edi, 0
        pushl %esi        /* info.args[3] = $esi; */
        .cfi_adjust_cfa_offset 4
        .cfi_rel_offset %esi, 0
        pushl %edx        /* info.args[2] = $edx; */
        .cfi_adjust_cfa_offset 4
        .cfi_rel_offset %edx, 0
        pushl %ecx        /* info.args[1] = $ecx; */
        .cfi_adjust_cfa_offset 4
        .cfi_rel_offset %ecx, 0
        pushl %ebx        /* info.args[0] = $ebx; */
        .cfi_adjust_cfa_offset 4
        .cfi_rel_offset %ebx, 0
        pushl %eax        /* info.no = $eax; */
        .cfi_adjust_cfa_offset 4

        /* $esp points at &info.  Push that pointer on the stack as
         * our arg for vsyscall_hook(). */
        movl %esp, %ecx
        pushl %ecx
        .cfi_adjust_cfa_offset 4

        call syscall_hook
        /* $eax = vsyscall_hook(&info); */

        /* $eax is now the syscall return value.  Erase the |&info|
         * arg and |info.no| from the stack so that we can restore the
         * other registers we saved. */
        addl $8, %esp
        .cfi_adjust_cfa_offset -8

        /* Contract of __kernel_vsyscall() and real syscalls is that even
         * callee-save registers aren't touched, so we restore everything
         * here. */
        popl %ebx
        .cfi_adjust_cfa_offset -4
        .cfi_restore %ebx
        popl %ecx
        .cfi_adjust_cfa_offset -4
        .cfi_restore %ecx
        popl %edx
        .cfi_adjust_cfa_offset -4
        .cfi_restore %edx
        popl %esi
        .cfi_adjust_cfa_offset -4
        .cfi_restore %esi
        popl %edi
        .cfi_adjust_cfa_offset -4
        .cfi_restore %edi
        popl %ebp
        .cfi_adjust_cfa_offset -4
        .cfi_restore %ebp

        ret
        .cfi_endproc
        .size _syscall_hook_trampoline, .-_syscall_hook_trampoline



        .global _syscall_hook_trampoline_3d_01_f0_ff_ff
        .hidden _syscall_hook_trampoline_3d_01_f0_ff_ff
        .type _syscall_hook_trampoline_3d_01_f0_ff_ff, @function
_syscall_hook_trampoline_3d_01_f0_ff_ff:
        .cfi_startproc

        call _syscall_hook_trampoline
        cmpl $0xfffff001,%eax
        ret

        .cfi_endproc
        .size _syscall_hook_trampoline_3d_01_f0_ff_ff, .-_syscall_hook_trampoline_3d_01_f0_ff_ff



#elif defined(__x86_64__)
        .text

        .global _syscall_hook_trampoline
        .hidden _syscall_hook_trampoline
        .type _syscall_hook_trampoline, @function
        .p2align 4
_syscall_hook_trampoline:
        .cfi_startproc
        /* Build a |struct syscall_info| on the stack by pushing the arguments
           and syscall number. */
        pushq %r9
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %r9, 0
        pushq %r8
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %r8, 0
        pushq %r10
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %r10, 0
        pushq %rdx
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %rdx, 0
        pushq %rsi
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %rsi, 0
        pushq %rdi
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %rdi, 0
        pushq %rax
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %rax, 0

        /* Call our hook. */
        mov %rsp, %rdi
        callq syscall_hook

        /* On entrance, we pushed the %rax, the syscall number. But we don't
           want to |pop %rax|, as that will overwrite our return value. Pop
           into %r11 instead. */
        pop %r11
        .cfi_adjust_cfa_offset -8

        /* We don't really *need* to restore these, since the kernel could have
           trashed them all anyway. But it seems reasonable to do so. */
        pop %rdi
        .cfi_adjust_cfa_offset -8
        .cfi_restore %rdi
        pop %rsi
        .cfi_adjust_cfa_offset -8
        .cfi_restore %rsi
        pop %rdx
        .cfi_adjust_cfa_offset -8
        .cfi_restore %rdx
        pop %r10
        .cfi_adjust_cfa_offset -8
        .cfi_restore %r10
        pop %r8
        .cfi_adjust_cfa_offset -8
        .cfi_restore %r8
        pop %r9
        .cfi_adjust_cfa_offset -8
        .cfi_restore %r9

        /* ...and we're done. */
        ret
        .cfi_endproc
        .size _syscall_hook_trampoline, . - _syscall_hook_trampoline



        .global _syscall_hook_trampoline_48_3d_01_f0_ff_ff
        .hidden _syscall_hook_trampoline_48_3d_01_f0_ff_ff
        .type _syscall_hook_trampoline_48_3d_01_f0_ff_ff, @function
_syscall_hook_trampoline_48_3d_01_f0_ff_ff:
        .cfi_startproc

        callq _syscall_hook_trampoline
        cmpq $0xfffffffffffff001,%rax
        ret

        .cfi_endproc
        .size _syscall_hook_trampoline_48_3d_01_f0_ff_ff, .-_syscall_hook_trampoline_48_3d_01_f0_ff_ff



        .global _syscall_hook_trampoline_48_3d_00_f0_ff_ff
        .hidden _syscall_hook_trampoline_48_3d_00_f0_ff_ff
        .type _syscall_hook_trampoline_48_3d_00_f0_ff_ff, @function
_syscall_hook_trampoline_48_3d_00_f0_ff_ff:
        .cfi_startproc

        callq _syscall_hook_trampoline
        cmpq $0xfffffffffffff000,%rax
        ret

        .cfi_endproc
        .size _syscall_hook_trampoline_48_3d_00_f0_ff_ff, .-_syscall_hook_trampoline_48_3d_00_f0_ff_ff



        .global _syscall_hook_trampoline_48_8b_3c_24
        .hidden _syscall_hook_trampoline_48_8b_3c_24
        .type _syscall_hook_trampoline_48_8b_3c_24, @function
_syscall_hook_trampoline_48_8b_3c_24:
        .cfi_startproc

        callq _syscall_hook_trampoline
        /* The original instruction after the syscall is movq (%rsp),%rdi.
           Because we pushed a return address and shifted RSP down
           before reaching this point, to get the equivalent behavior we
           need to use this offset. */
        movq (8 + _syscall_stack_adjust)(%rsp),%rdi
        ret

        .cfi_endproc
        .size _syscall_hook_trampoline_48_8b_3c_24, .-_syscall_hook_trampoline_48_8b_3c_24



        .global _syscall_hook_trampoline_5a_5e_c3
        .hidden _syscall_hook_trampoline_5a_5e_c3
        .type _syscall_hook_trampoline_5a_5e_c3, @function
_syscall_hook_trampoline_5a_5e_c3:
        .cfi_startproc

        callq _syscall_hook_trampoline
        /* The original instructions after the syscall are
           pop %rdx; pop %rsi; retq. */
        pop %rdx /* Return address, ignored */
        /* We're not returning to the dynamically generated stub, so
           we need to fix the stack pointer ourselves. */
        add $_syscall_stack_adjust,%rsp
        pop %rdx
        pop %rsi
        ret

        .cfi_endproc
        .size _syscall_hook_trampoline_5a_5e_c3, .-_syscall_hook_trampoline_5a_5e_c3



        .global _syscall_hook_trampoline_90_90_90
        .hidden _syscall_hook_trampoline_90_90_90
        .type _syscall_hook_trampoline_90_90_90, @function
_syscall_hook_trampoline_90_90_90:
        .cfi_startproc

        jmp _syscall_hook_trampoline

        .cfi_endproc
        .size _syscall_hook_trampoline_90_90_90, .-_syscall_hook_trampoline_90_90_90
#endif /* __x86_64__ */

        .global _code_buffer
        .hidden _code_buffer
_code_buffer:
        /* This size must match SYSCALL_HOOK_CODE_BUFFER_SIZE */
        .space 0x10000,0xFF

        .section .note.GNU-stack,"",@progbits
