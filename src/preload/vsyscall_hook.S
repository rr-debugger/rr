#if defined(__i386__)
/**
 * Call this hook from |__kernel_vsyscall()|, to buffer syscalls that
 * we otherwise couldn't wrap through LD_PRELOAD helpers.  Return the
 * *RAW* kernel return value, not the -1/errno mandated by POSIX.
 *
 * Remember, this function runs *below* the level of libc.  libc can't
 * know that its call to |__kernel_vsyscall()| has been re-routed to
 * us.
 */
        .text
        .global _vsyscall_hook_trampoline
        .hidden _vsyscall_hook_trampoline
        .type _vsyscall_hook_trampoline, @function
_vsyscall_hook_trampoline:
        .cfi_startproc

        /* The monkeypatch pushed $eax on the stack, but there's no
         * CFI info for it.  Fix up the CFA offset here to account for
         * the monkeypatch code. */
        .cfi_adjust_cfa_offset 4
        .cfi_rel_offset %eax, 0

        /* Pull $eax back off the stack.  Now our syscall-arg
         * registers are restored to their state on entry to
         * __kernel_vsyscall(). */
        popl %eax
        .cfi_adjust_cfa_offset -4
        .cfi_restore %eax

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
         * our arg for syscall_hook(). */
        movl %esp, %ecx
        pushl %ecx
        .cfi_adjust_cfa_offset 4

        call vsyscall_hook
        /* $eax = vsyscall_hook(&info); */

        /* $eax is now the syscall return value.  Erase the |&info|
         * arg and |info.no| from the stack so that we can restore the
         * other registers we saved. */
        addl $8, %esp
        .cfi_adjust_cfa_offset -8

        /* Contract of __kernel_vsyscall() is that even callee-save
         * registers aren't touched, so we restore everything here. */
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

        /* Return to the caller of *|__kernel_vsyscall()|*, because
         * the monkeypatch jumped to us. */
        ret
        .cfi_endproc
        .size _vsyscall_hook_trampoline, .-_vsyscall_hook_trampoline
#elif defined(__x86_64__)

        .text

        .global syscall_raw_trampoline
        .hidden syscall_raw_trampoline
        .type syscall_raw_trampoline, @function
	.p2align 4
syscall_raw_trampoline:
        .cfi_startproc
        /* Build a |struct syscall_info| on the stack by pushing the arguments
           and syscall number.  Pushing seven items onto the stack also has the
           pleasant side-effect of ensuring that the stack is properly aligned
           for the call to vsyscall_hook.  */
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

        /* Call our hook.  */
        movq %rsp, %rdi
        callq vsyscall_hook

        /* On entrance, we pushed %rax, the syscall number.  But we don't
           want to |pop %rax|, as that will overwrite our return value.  Pop
           into %r11 instead. */
        popq %r11
        .cfi_adjust_cfa_offset -8

        /* We don't really *need* to restore these, since the kernel could have
           trashed them all anyway.  But it seems reasonable to do so.  */
        popq %rdi
        .cfi_adjust_cfa_offset -8
	.cfi_restore %rdi
        popq %rsi
        .cfi_adjust_cfa_offset -8
	.cfi_restore %rsi
        popq %rdx
        .cfi_adjust_cfa_offset -8
	.cfi_restore %rdx
        popq %r10
        .cfi_adjust_cfa_offset -8
	.cfi_restore %r10
        popq %r8
        .cfi_adjust_cfa_offset -8
	.cfi_restore %r8
        popq %r9
        .cfi_adjust_cfa_offset -8
	.cfi_restore %r9

        /* Our monkeypatch edited out the |cmp $-4095, %rax| needed to properly
           set errno on the way out of the function.  Set the flags here so
           the subsequent |jae| instruction has something to go on.  */
        cmpq $-4095, %rax

        /* ...and we're done.  */
        ret
        .cfi_endproc
        .size syscall_raw_trampoline, . - syscall_raw_trampoline

#endif /* __i386__ */

        .section .note.GNU-stack,"",@progbits
