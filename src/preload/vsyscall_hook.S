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

	movl $vsyscall_hook, %eax
	call *%eax        /* $eax = vsyscall_hook(&info); */

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

	.global get_vsyscall_hook_trampoline
	.type get_vsyscall_hook_trampoline, @function
get_vsyscall_hook_trampoline:
	.cfi_startproc
	call .L2
.L2:
	pop %eax
	addl $(_vsyscall_hook_trampoline - .L2), %eax
	ret
	.cfi_endproc
	.size get_vsyscall_hook_trampoline, .-get_vsyscall_hook_trampoline

	.section .note.GNU-stack,"",@progbits
