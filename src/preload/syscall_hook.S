#if defined(__aarch64__)
        .set preload_thread_locals,0x70010000
#else
        .set preload_thread_locals,0x70001000
#endif

        .global _syscallbuf_code_start
        .hidden _syscallbuf_code_start

        .global _syscallbuf_final_exit_instruction
        .hidden _syscallbuf_final_exit_instruction
        .type _syscallbuf_final_exit_instruction, @function

#define DW_OP_CONST4U(val)                      \
        0x0c, /* DW_OP_const4u */               \
        /* Individually place bytes */          \
        (val) & 0xFF,                           \
        ((val) & (0xFF <<  0x8)) >>  0x8,       \
        ((val) & (0xFF << 0x10)) >> 0x10,       \
        ((val) & (0xFF << 0x18)) >> 0x18

#define DW_OP_CONST8U(val)                      \
        0x0e, /* DW_OP_const8u */               \
        /* Individually place bytes */          \
        (val) & 0xFF,                           \
        ((val) & (0xFF <<  0x8)) >>  0x8,       \
        ((val) & (0xFF << 0x10)) >> 0x10,       \
        ((val) & (0xFF << 0x18)) >> 0x18,       \
        ((val) & (0xFF << 0x20)) >> 0x20,       \
        ((val) & (0xFF << 0x28)) >> 0x28,       \
        ((val) & (0xFF << 0x30)) >> 0x30,       \
        ((val) & (0xFF << 0x38)) >> 0x38

#define REG_AT_ADDR32(reg, addr)                                \
        .cfi_escape 0x10, /* DW_CFA_expression */               \
                    reg,                                        \
                    0x05, /* 5 byte expression follows */       \
                    DW_OP_CONST4U(addr)
#define REG_AT_ADDR64(reg, addr)                                \
        .cfi_escape 0x10, /* DW_CFA_expression */               \
                    reg,                                        \
                    0x09, /* 9 byte expression follows */       \
                    DW_OP_CONST8U(addr)

// 10 bytes LEB128 is enough to encode 64bit integer and we shouldn't
// really need anything longer than that.
#define COUNT_LEB128(lebs...)                                   \
        _COUNT_LEB128(lebs, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1)
#define _COUNT_LEB128(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, N, ...) N

#define REG_AT_REG_OFFSET(reg, base, lebs...)                                   \
        .cfi_escape 0x10, /* DW_CFA_expression */                               \
                    reg,                                                        \
                    (COUNT_LEB128(lebs) + 1), /* 1 byte + LEB128 bytes */       \
                    (0x70 + base), /* DW_OP_breg0 + base */                     \
                    lebs

#if defined(__i386__)
.text
.set syscallbuf_stub_alt_stack, preload_thread_locals
.set stub_scratch_1, preload_thread_locals + 8
.set alt_stack_nesting_level, preload_thread_locals + 12
.set saved_flags, preload_thread_locals + 16

.p2align 4

_syscallbuf_code_start:
/* Insert a NOP here so we have no symbol clashes. Otherwise
   in some configurations (gdb 7.7.1, Ubuntu 14.04) gdb sometimes gets confused.
 */
        nop


_syscallbuf_final_exit_instruction:
        jmp *(stub_scratch_1)

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
         * our arg for vsyscall_hook().
         * Use %ebp as our temporary CFA register here. Don't use %ebx or
         * any other GP register, since x86-64 gdb 7.7 (at least) treats all GP
         * regs other than %esp/%ebp as *signed* and sign-extends their values.
         * Having some CFA values sign-extended and others not breaks gdb
         * stack walking.
         */
        movl %esp, %ebp
        .cfi_def_cfa_register %ebp

        /* Align stack to 16 bytes */
        and $0xfffffff0,%esp

        /* Save XMM registers */
        sub $0x80,%esp
        movdqa %xmm0,(%esp)
        movdqa %xmm1,0x10(%esp)
        movdqa %xmm2,0x20(%esp)
        movdqa %xmm3,0x30(%esp)
        movdqa %xmm4,0x40(%esp)
        movdqa %xmm5,0x50(%esp)
        movdqa %xmm6,0x60(%esp)
        movdqa %xmm7,0x70(%esp)

        sub $12,%esp
        pushl %ebp

        call syscall_hook
        /* $eax = vsyscall_hook(&info); */

        movdqa 0x10(%esp),%xmm0
        movdqa 0x20(%esp),%xmm1
        movdqa 0x30(%esp),%xmm2
        movdqa 0x40(%esp),%xmm3
        movdqa 0x50(%esp),%xmm4
        movdqa 0x60(%esp),%xmm5
        movdqa 0x70(%esp),%xmm6
        movdqa 0x80(%esp),%xmm7

        mov $saved_flags, %esp
        popfw
        /* From here on, non-application flag changes are not allowed */

        /* Restore ESP */
        mov %ebp, %esp
        .cfi_def_cfa_register %esp

        /* $eax is now the syscall return value.  Erase |info.no| from the
         * stack so that we can restore the other registers we saved. */
        lea 4(%esp),%esp
        .cfi_adjust_cfa_offset -4

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
        mov (alt_stack_nesting_level),%ebp
        lea -1(%ebp),%ebp
        mov %ebp,(alt_stack_nesting_level)
        popl %ebp
        .cfi_adjust_cfa_offset -4
        .cfi_restore %ebp

        ret
        .cfi_endproc
        .size _syscall_hook_trampoline, .-_syscall_hook_trampoline

#define SYSCALLHOOK_START(name) \
       .global name;            \
       .hidden name;            \
       .type name, @function;   \
name:                           \
       .cfi_startproc;          \
       .cfi_def_cfa_offset 0;   \
       .cfi_offset %eip, 0;     \
       .cfi_offset %esp, 4

#define SYSCALLHOOK_END(name)                                   \
        pop (stub_scratch_1);                                   \
        .cfi_adjust_cfa_offset -4;                              \
        pop %esp;                                               \
        .cfi_same_value %esp;                                   \
        REG_AT_ADDR32(0x08 /* %eip */, stub_scratch_1);         \
        jmp _syscallbuf_final_exit_instruction;                 \
       .cfi_endproc;                                            \
       .size name, .-name

SYSCALLHOOK_START(_syscall_hook_trampoline_3d_01_f0_ff_ff)
        call _syscall_hook_trampoline
        cmpl $0xfffff001,%eax
SYSCALLHOOK_END(_syscall_hook_trampoline_3d_01_f0_ff_ff)

SYSCALLHOOK_START(_syscall_hook_trampoline_90_90_90)
        call _syscall_hook_trampoline
SYSCALLHOOK_END(_syscall_hook_trampoline_90_90_90)

/* Declare gcc get_pc thunks here so they're in a known region of code */

        .global _get_pc_thunks_start
        .hidden _get_pc_thunks_start
_get_pc_thunks_start:

#define THUNK(name, reg) \
        .section        .text.__x86.get_pc_thunk.name,"axG",@progbits,__x86.get_pc_thunk.name,comdat; \
        .global  __x86.get_pc_thunk.name; \
        .hidden __x86.get_pc_thunk.name; \
        .type   __x86.get_pc_thunk.name, @function; \
__x86.get_pc_thunk.name: \
        .cfi_startproc; \
        movl    (%esp), %reg; \
        ret; \
        .cfi_endproc

THUNK(ax, eax)
THUNK(bx, ebx)
THUNK(cx, ecx)
THUNK(dx, edx)
THUNK(si, esi)
THUNK(di, edi)
THUNK(bp, ebp)

        .global _get_pc_thunks_end
        .hidden _get_pc_thunks_end
_get_pc_thunks_end:

#elif defined(__x86_64__)
        .text

        .set stub_scratch_1, preload_thread_locals + 16
        .set alt_stack_nesting_level, preload_thread_locals + 24
        .set saved_flags, preload_thread_locals + 28

        .p2align 4
_syscallbuf_code_start:

_syscall_hook_trampoline:
        .cfi_startproc
        /* Save RBX because we need a callee-saves register */
        pushq %rbx
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %rbx, 0

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

        /* Align stack */
        mov %rsp,%rbx
        .cfi_def_cfa_register %rbx
        and $0xfffffffffffffff0,%rsp

        /* Save XMM registers */
        sub $0x80,%rsp
        movdqa %xmm0,(%rsp)
        movdqa %xmm1,0x10(%rsp)
        movdqa %xmm2,0x20(%rsp)
        movdqa %xmm3,0x30(%rsp)
        movdqa %xmm4,0x40(%rsp)
        movdqa %xmm5,0x50(%rsp)
        movdqa %xmm6,0x60(%rsp)
        movdqa %xmm7,0x70(%rsp)

        /* Save registers that aren't callee-saves preserved by syscall_hook,
           and that we aren't already restoring from the syscall args */
        push %rcx
        push %r11
        /* stack is 16-byte aligned again for entry to C */

        /* Call our hook. */
        mov %rbx,%rdi
        callq syscall_hook

        pop %r11
        pop %rcx

        /* Restore XMM registers */
        movdqa (%rsp),%xmm0
        movdqa 0x10(%rsp),%xmm1
        movdqa 0x20(%rsp),%xmm2
        movdqa 0x30(%rsp),%xmm3
        movdqa 0x40(%rsp),%xmm4
        movdqa 0x50(%rsp),%xmm5
        movdqa 0x60(%rsp),%xmm6
        movdqa 0x70(%rsp),%xmm7

        mov $saved_flags, %rsp
        popfw
        /* From here on, non-application flag changes are not allowed */

        mov %rbx,%rsp
        .cfi_def_cfa_register %rsp

        /* On entrance, we pushed the %rax, the syscall number. But we don't
           want to |pop %rax|, as that will overwrite our return value. Skip over it. */
        pop %rdi
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
        mov (alt_stack_nesting_level),%r9d
        lea -1(%r9),%r9
        mov %r9d,(alt_stack_nesting_level)
        pop %r9
        .cfi_adjust_cfa_offset -8
        .cfi_restore %r9

        pop %rbx
        .cfi_adjust_cfa_offset -8
        .cfi_restore %rbx

        /* ...and we're done. */
        ret
        .cfi_endproc
        .size _syscall_hook_trampoline, . - _syscall_hook_trampoline

_syscallbuf_final_exit_instruction:
        jmp *(stub_scratch_1)

/**
 * Ok, bear with me here. When gdb sees our stack switch, it gets suspicious and if
 * we're unlucky may decide that our unwind info is broken and abort the unwind. However,
 * it decides to allow the unwind to proceed anyway if we happen to be in a function called
 * __morestack (because that's what gcc calls its stack switching mechanism). Now,
 * GDB does the stack switching comparison based on the CFA. What we thus need to do is keep the
 * CFA pointing to the old stack until we get to a function named __morestack. We set the CFA for every
 * syscallhook to what it will be at the end of the function (which, well, is an ok definition
 * of the CFA). Then, we insert a __morestack function (still with the old CFA) that just jumps
 * through to the trampoline. This way, we can force gdb's stack switch detection to think the
 * stack switch happens between the hook and the common trampoline code (and add a __morestack
 * local symbol to the trampoline code to avoid GDB messing with our stack trace).
 */
#define CFA_AT_RSP_OFFSET(offset) \
.cfi_escape 0x0f, /* DW_CFA_def_cfa_expression */\
        0x03, /* 3 bytes follow */\
        0x77, offset, /* DW_OP_breg7, offset */\
        0x06; /* DW_OP_deref */

#define RSP_IS_CFA \
.cfi_escape 0x16, /* DW_CFA_val_expression */\
            0x7,  /* %rsp */\
            0;     /* 0 bytes follow */

#define RSP_IS_CFA_PLUS_OFFSET(offset) \
.cfi_escape 0x16, /* DW_CFA_val_expression */\
            0x7,  /* %rsp */\
            2,     /* 2 bytes follow */\
            0x23, /* DW_OP_plus_uconst */\
            offset;

#define RSP_IS_RSP_PLUS_OFFSET(offset) \
.cfi_escape 0x16, /* DW_CFA_val_expression */\
            0x07, /* %rsp */\
            0x02, /* 2 bytes follow */\
            0x77, offset; /* DW_OP_breg7, offset */

#define RIP_IS_DEREF_RSP(offset) REG_AT_REG_OFFSET(0x10 /* %rip */, 7, offset)

/**
 * On syscallhook entry, the stack has been switched to the end of per-task
 * scratch space, then the old RSP and the return address have been pushed.
 */
#define SYSCALLHOOK_START(name)    \
        .global name;              \
        .hidden name;              \
        .type name, @function;     \
name:                              \
        .cfi_startproc;            \
        CFA_AT_RSP_OFFSET(8)       \
        RSP_IS_CFA                 \
        RIP_IS_DEREF_RSP(0)

#define SYSCALLHOOK_END(name)                                   \
        pop (stub_scratch_1);                                   \
        CFA_AT_RSP_OFFSET(0)                                    \
        REG_AT_ADDR32(0x10 /* %rip */, stub_scratch_1);         \
        pop %rsp;                                               \
        .cfi_def_cfa %rsp, 0;                                   \
        jmp _syscallbuf_final_exit_instruction;                 \
        .cfi_endproc;                                           \
        .size name, .-name

/* See note above on what __morestack is for */
.global __morestack
.hidden __morestack
.type __morestack, @function
__morestack:
.cfi_startproc
CFA_AT_RSP_OFFSET(16)
RSP_IS_RSP_PLUS_OFFSET(8)
RIP_IS_DEREF_RSP(0)
callq _syscall_hook_trampoline
/* GDB likes to override valid CFI with its own heuristics if the current
   instruction is a retq. This becomes a problem here, because GDB will set
   a breakpoint at the next instruction after the callq when continuing out of
   `_syscall_hook_trampoline`. This `nop` makes said instruction not a retq,
   thus preventing that GDB heuristic from kicking in and letting GDB realize
   that it did in fact manage to step out of the `_syscall_hook_trampoline`
   frame. */
nop
retq
.cfi_endproc
.size __morestack, .-__morestack

SYSCALLHOOK_START(_syscall_hook_trampoline_48_3d_01_f0_ff_ff)
        callq __morestack
        cmpq $0xfffffffffffff001,%rax
SYSCALLHOOK_END(_syscall_hook_trampoline_48_3d_01_f0_ff_ff)

SYSCALLHOOK_START(_syscall_hook_trampoline_48_3d_00_f0_ff_ff)
        callq __morestack
        cmpq $0xfffffffffffff000,%rax
SYSCALLHOOK_END(_syscall_hook_trampoline_48_3d_00_f0_ff_ff)

SYSCALLHOOK_START(_syscall_hook_trampoline_48_85_c0)
        callq __morestack
        test %rax,%rax
SYSCALLHOOK_END(_syscall_hook_trampoline_48_85_c0)

SYSCALLHOOK_START(_syscall_hook_trampoline_3d_00_f0_ff_ff)
        callq __morestack
        cmpl $0xfffff000,%eax
SYSCALLHOOK_END(_syscall_hook_trampoline_3d_00_f0_ff_ff)

SYSCALLHOOK_START(_syscall_hook_trampoline_48_89_45_f8)
        callq __morestack
        mov %rax,-8(%rbp)
SYSCALLHOOK_END(_syscall_hook_trampoline_48_89_45_f8)

SYSCALLHOOK_START(_syscall_hook_trampoline_48_89_c3)
        callq __morestack
        mov %rax,%rbx
SYSCALLHOOK_END(_syscall_hook_trampoline_48_89_c3)

SYSCALLHOOK_START(_syscall_hook_trampoline_48_8b_3c_24)
         callq __morestack
         /* The original instruction after the syscall is movq (%rsp),%rdi. */
         movq 8(%rsp),%rdi
         movq (%rdi),%rdi
SYSCALLHOOK_END(_syscall_hook_trampoline_48_8b_3c_24)

SYSCALLHOOK_START(_syscall_hook_trampoline_4c_8b_0d)
        callq __morestack
        push %rax
        push %rbx
        /* Get return address into %rbx */
        mov 16(%rsp),%rbx
        /* Get PC-relative offset of patched instruction into %eax */
        mov -4(%rbx),%eax
        movsx %eax,%rax
        mov (%rbx,%rax),%r9
        pop %rbx
        pop %rax
SYSCALLHOOK_END(_syscall_hook_trampoline_4c_8b_0d)

SYSCALLHOOK_START(_syscall_hook_trampoline_5a_5e_c3)
        .cfi_offset %rip, 16
        RSP_IS_CFA_PLUS_OFFSET(24)
        callq __morestack
        /* The original instructions after the syscall are
           pop %rdx; pop %rsi; retq. */
        /* We're not returning to the dynamically generated stub, so
           we need to fix the stack pointer ourselves. */
        pop %rdx
        CFA_AT_RSP_OFFSET(0)
        pop %rsp
        .cfi_def_cfa %rsp, 0;
        pop %rdx
        .cfi_adjust_cfa_offset -8
        pop %rsi
        .cfi_adjust_cfa_offset -8
        pop (stub_scratch_1)
        .cfi_adjust_cfa_offset -8
        jmp _syscallbuf_final_exit_instruction

        .cfi_endproc
        .size _syscall_hook_trampoline_5a_5e_c3, .-_syscall_hook_trampoline_5a_5e_c3

SYSCALLHOOK_START(_syscall_hook_trampoline_89_c2_f7_da)
        call __morestack
        mov %eax,%edx
        neg %edx
SYSCALLHOOK_END(_syscall_hook_trampoline_89_c2_f7_da)

SYSCALLHOOK_START(_syscall_hook_trampoline_90_90_90)
        call __morestack
SYSCALLHOOK_END(_syscall_hook_trampoline_90_90_90)

SYSCALLHOOK_START(_syscall_hook_trampoline_ba_01_00_00_00)
        call __morestack
        mov $1,%edx
SYSCALLHOOK_END(_syscall_hook_trampoline_ba_01_00_00_00)

SYSCALLHOOK_START(_syscall_hook_trampoline_89_c1_31_d2)
        call __morestack
        mov %eax,%ecx
        xor %edx,%edx
SYSCALLHOOK_END(_syscall_hook_trampoline_89_c1_31_d2)

SYSCALLHOOK_START(_syscall_hook_trampoline_c3_nop)
        .cfi_offset %rip, 16
        RSP_IS_CFA_PLUS_OFFSET(24)
        callq __morestack
        /* The original instructions after the syscall are
           retq; nopl 0x0(%rax,%rax,1) */
        /* We're not returning to the dynamically generated stub, so
           we need to fix the stack pointer ourselves. */
        pop %rdx
        CFA_AT_RSP_OFFSET(0)
        pop %rsp
        .cfi_def_cfa %rsp, 0;
        pop (stub_scratch_1)
        .cfi_adjust_cfa_offset -8
        jmp _syscallbuf_final_exit_instruction

        .cfi_endproc
        .size _syscall_hook_trampoline_c3_nop, .-_syscall_hook_trampoline_c3_nop

SYSCALLHOOK_START(_syscall_hook_trampoline_40_80_f6_81)
	xor $0x81, %sil
	call __morestack
SYSCALLHOOK_END(_syscall_hook_trampoline_40_80_f6_81)

SYSCALLHOOK_START(_syscall_hook_trampoline_48_8d_b3_f0_08_00_00)
	lea    0x8f0(%rbx),%rsi
        callq __morestack
SYSCALLHOOK_END(_syscall_hook_trampoline_48_8d_b3_f0_08_00_00)

SYSCALLHOOK_START(_syscall_hook_trampoline_49_89_ca)
	mov %rcx, %r10
	call __morestack
SYSCALLHOOK_END(_syscall_hook_trampoline_49_89_ca)

SYSCALLHOOK_START(_syscall_hook_trampoline_48_89_c1)
        callq __morestack
        mov %rax, %rcx
SYSCALLHOOK_END(_syscall_hook_trampoline_48_89_c1)

#define MOV_RDX_VARIANTS \
  MOV_RDX_TO_REG(48, d0) \
  MOV_RDX_TO_REG(48, d1) \
  MOV_RDX_TO_REG(48, d2) \
  MOV_RDX_TO_REG(48, d3) \
  MOV_RDX_TO_REG(48, d4) \
  MOV_RDX_TO_REG(48, d5) \
  MOV_RDX_TO_REG(48, d6) \
  MOV_RDX_TO_REG(48, d7) \
  MOV_RDX_TO_REG(49, d0) \
  MOV_RDX_TO_REG(49, d1) \
  MOV_RDX_TO_REG(49, d2) \
  MOV_RDX_TO_REG(49, d3) \
  MOV_RDX_TO_REG(49, d4) \
  MOV_RDX_TO_REG(49, d5) \
  MOV_RDX_TO_REG(49, d6) \
  MOV_RDX_TO_REG(49, d7)

#define MOV_RDX_TO_REG(rex, op) \
SYSCALLHOOK_START(_syscall_hook_trampoline_##rex##_89_##op); \
        callq __morestack;                                   \
        .byte 0x##rex, 0x89, 0x##op;                         \
SYSCALLHOOK_END(_syscall_hook_trampoline_##rex##_89_##op);

  MOV_RDX_VARIANTS

SYSCALLHOOK_START(_syscall_hook_trampoline_48_c1_e2_20)
        callq __morestack
        shl $32, %rdx
SYSCALLHOOK_END(_syscall_hook_trampoline_48_c1_e2_20)

SYSCALLHOOK_START(_syscall_hook_trampoline_49_8b_44_24_28)
        callq __morestack
        mov 0x28(%r12),%rax
SYSCALLHOOK_END(_syscall_hook_trampoline_49_8b_44_24_28)

SYSCALLHOOK_START(_syscall_hook_trampoline_4c_89_f7)
        mov %r14, %rdi
        callq __morestack
SYSCALLHOOK_END(_syscall_hook_trampoline_4c_89_f7)

SYSCALLHOOK_START(_syscall_hook_trampoline_4c_89_ff)
        mov %r15, %rdi
        callq __morestack
SYSCALLHOOK_END(_syscall_hook_trampoline_4c_89_ff)

SYSCALLHOOK_START(_syscall_hook_trampoline_49_c7_c1_ff_ff_ff_ff)
        mov $0xffffffffffffffff,%r9
        callq __morestack
SYSCALLHOOK_END(_syscall_hook_trampoline_49_c7_c1_ff_ff_ff_ff)

SYSCALLHOOK_START(_syscall_hook_trampoline_b8_0e_00_00_00)
        mov $0x0e,%eax
        callq __morestack
SYSCALLHOOK_END(_syscall_hook_trampoline_b8_0e_00_00_00)

SYSCALLHOOK_START(_syscall_hook_trampoline_b8_11_01_00_00)
        mov $0x111,%eax
        callq __morestack
SYSCALLHOOK_END(_syscall_hook_trampoline_b8_11_01_00_00)

SYSCALLHOOK_START(_syscall_hook_trampoline_b8_ca_00_00_00)
        mov $0xca,%eax
        callq __morestack
SYSCALLHOOK_END(_syscall_hook_trampoline_b8_ca_00_00_00)

SYSCALLHOOK_START(_syscall_hook_trampoline_be_18_00_00_00)
        mov $0x18,%esi
        callq __morestack
SYSCALLHOOK_END(_syscall_hook_trampoline_be_18_00_00_00)

SYSCALLHOOK_START(_syscall_hook_trampoline_48_89_e5)
        /* Previous RSP is stored on the stack above our return address */
        mov 8(%rsp),%rbp
        callq __morestack
SYSCALLHOOK_END(_syscall_hook_trampoline_48_89_e5)

SYSCALLHOOK_START(_syscall_hook_trampoline_48_8b_45_10)
        mov    0x10(%rbp),%rax
        callq __morestack
SYSCALLHOOK_END(_syscall_hook_trampoline_48_8b_45_10)

SYSCALLHOOK_START(_syscall_hook_trampoline_48_89_fb)
        mov %rdi,%rbx
        callq __morestack
SYSCALLHOOK_END(_syscall_hook_trampoline_48_89_fb)

SYSCALLHOOK_START(_syscall_hook_trampoline_nops)
        callq __morestack
SYSCALLHOOK_END(_syscall_hook_trampoline_nops)

#elif defined(__aarch64__)
        .text

        .set syscallbuf_stub_alt_stack, preload_thread_locals
        .set stub_scratch_1, preload_thread_locals + 16
        .set alt_stack_nesting_level, preload_thread_locals + 24
        .set stub_scratch_2, preload_thread_locals + 8 * 13

// Store a pair of x registers to stack at offset sp.
// Assuming that CFA register is sp
#define STPX_STACK(r1, r2, offset)              \
        stp     x##r1, x##r2, [sp, offset];     \
        .cfi_rel_offset x##r1, offset;          \
        .cfi_rel_offset x##r2, offset + 8

#define LDPX_STACK(r1, r2, offset)              \
        ldp     x##r1, x##r2, [sp, offset];     \
        .cfi_same_value x##r1;                  \
        .cfi_same_value x##r2

// Store a pair of q registers to stack at offset sp.
// Assuming that CFA register is sp
#define STPQ_STACK(r1, r2, offset)              \
        stp     q##r1, q##r2, [sp, offset];     \
        .cfi_rel_offset q##r1, offset;          \
        .cfi_rel_offset q##r2, offset + 16

#define LDPQ_STACK(r1, r2, offset)              \
        ldp     q##r1, q##r2, [sp, offset];     \
        .cfi_same_value q##r1;                  \
        .cfi_same_value q##r2

// Mark all temporary registers as same_value except x8 and x15
#define SAME_VALUE_X_NO8_NO15   \
        .cfi_same_value x0;     \
        .cfi_same_value x1;     \
        .cfi_same_value x2;     \
        .cfi_same_value x3;     \
        .cfi_same_value x4;     \
        .cfi_same_value x5;     \
        .cfi_same_value x6;     \
        .cfi_same_value x7;     \
        .cfi_same_value x9;     \
        .cfi_same_value x10;    \
        .cfi_same_value x11;    \
        .cfi_same_value x12;    \
        .cfi_same_value x13;    \
        .cfi_same_value x14;    \
        .cfi_same_value x16;    \
        .cfi_same_value x17;    \
        .cfi_same_value x18

#define SAME_VALUE_X            \
        SAME_VALUE_X_NO8_NO15;  \
        .cfi_same_value x8;     \
        .cfi_same_value x15

#define SAME_VALUE_ALL_Q        \
        .cfi_same_value q0;     \
        .cfi_same_value q1;     \
        .cfi_same_value q2;     \
        .cfi_same_value q3;     \
        .cfi_same_value q4;     \
        .cfi_same_value q5;     \
        .cfi_same_value q6;     \
        .cfi_same_value q7;     \
        .cfi_same_value q8;     \
        .cfi_same_value q9;     \
        .cfi_same_value q10;    \
        .cfi_same_value q11;    \
        .cfi_same_value q12;    \
        .cfi_same_value q13;    \
        .cfi_same_value q14;    \
        .cfi_same_value q15;    \
        .cfi_same_value q16;    \
        .cfi_same_value q17;    \
        .cfi_same_value q18;    \
        .cfi_same_value q19;    \
        .cfi_same_value q20;    \
        .cfi_same_value q21;    \
        .cfi_same_value q22;    \
        .cfi_same_value q23;    \
        .cfi_same_value q24;    \
        .cfi_same_value q25;    \
        .cfi_same_value q26;    \
        .cfi_same_value q27;    \
        .cfi_same_value q28;    \
        .cfi_same_value q29;    \
        .cfi_same_value q30;    \
        .cfi_same_value q31

        .p2align 4
_syscallbuf_code_start:

_syscall_hook_trampoline:
        // stack frame:
        // 208-688: q2 - q31
        // 128-200: x10 - x18
        // 112-128: x7, x9
        // 104-112: x6
        // 48-104: syscall_info
        // 32-48: x29, x30
        // 0-32: q0, q1
        .cfi_startproc
        // GAS correctly put these in CIE as long as they
        // appears right after .cfi_startproc
        SAME_VALUE_X
        SAME_VALUE_ALL_Q
        // Store the vector registers at the bottom so that we can take advantage of
        // the larger pre-offset that can be encoded in the instruction
        // to adjust the stack pointer.
        stp     q0, q1, [sp, -688]!
        .cfi_def_cfa_offset 688
        .cfi_rel_offset q0, 0
        .cfi_rel_offset q1, 0 + 16
        STPX_STACK(29, 30, 32)
        /* Build a |struct syscall_info| on the stack by pushing the arguments
           and syscall number. */
        STPX_STACK(8, 0, 48)
        add     x0, sp, 48 // x0 saved, store new argument for syscall_hook in x0.
        STPX_STACK(1, 2, 64)
        STPX_STACK(3, 4, 80)
        STPX_STACK(5, 6, 96)
        STPX_STACK(7, 9, 112)
        STPX_STACK(10, 11, 128)
        STPX_STACK(12, 13, 144)
        STPX_STACK(14, 15, 160)
        STPX_STACK(16, 17, 176)
        str     x18, [sp, 192]
        .cfi_rel_offset x18, 192
        STPQ_STACK(2, 3, 208)
        STPQ_STACK(4, 5, 240)
        STPQ_STACK(6, 7, 272)
        // function call only maintain the bottom half of v8-v15
        // whereas syscall maintains all the v registers
        // so we actually need to save and restore v8-v15 as well...
        // (in principle we could save only the upper half but
        //  that's too much effort especially for the unwind info...)
        STPQ_STACK(8, 9, 304)
        STPQ_STACK(10, 11, 336)
        STPQ_STACK(12, 13, 368)
        STPQ_STACK(14, 15, 400)
        STPQ_STACK(16, 17, 432)
        STPQ_STACK(18, 19, 464)
        STPQ_STACK(20, 21, 496)
        STPQ_STACK(22, 23, 528)
        STPQ_STACK(24, 25, 560)
        STPQ_STACK(26, 27, 592)
        STPQ_STACK(28, 29, 624)
        STPQ_STACK(30, 31, 656)

        bl      syscall_hook

        movz    x29, #:abs_g1:alt_stack_nesting_level // assume 32bit address
        movk    x29, #:abs_g0_nc:alt_stack_nesting_level
        ldr     w30, [x29]
        sub     w30, w30, 1
        str     w30, [x29]

        ldp     x29, x30, [sp, 32]
        .cfi_same_value x29
        // x30 should not use same_value since it's value is changed
        // by the function call instruction
        .cfi_restore x30
        ldr     x8, [sp, 48]
        .cfi_same_value x8
        LDPX_STACK(1, 2, 64)
        LDPX_STACK(3, 4, 80)
        LDPX_STACK(5, 6, 96)
        LDPX_STACK(7, 9, 112)
        LDPX_STACK(10, 11, 128)
        LDPX_STACK(14, 15, 160)
        LDPX_STACK(16, 17, 176)
        ldr     x18, [sp, 192]
        .cfi_same_value x18

        LDPQ_STACK(2, 3, 208)
        LDPQ_STACK(4, 5, 240)
        LDPQ_STACK(6, 7, 272)
        LDPQ_STACK(8, 9, 304)
        LDPQ_STACK(10, 11, 336)
        LDPQ_STACK(12, 13, 368)
        LDPQ_STACK(14, 15, 400)
        LDPQ_STACK(16, 17, 432)
        LDPQ_STACK(18, 19, 464)
        LDPQ_STACK(20, 21, 496)
        LDPQ_STACK(22, 23, 528)
        LDPQ_STACK(24, 25, 560)
        LDPQ_STACK(26, 27, 592)
        LDPQ_STACK(28, 29, 624)
        LDPQ_STACK(30, 31, 656)

        ldp     q0, q1, [sp], 688
        .cfi_same_value q0
        .cfi_same_value q1
        .cfi_def_cfa_offset 0
        ret
        .cfi_endproc
        .size   _syscall_hook_trampoline, .-_syscall_hook_trampoline

/**
 * On syscallhook entry, we are still on the old stack,
 * with x30 (lr) points to right after the blr instruction that got us here.
 * The old values of x15 and x30 are saved to [x8], which is the syscall number
 * with an offset to land in the stub_scratch_2 area.
 */
        .globl _syscall_hook_trampoline_raw
        .hidden _syscall_hook_trampoline_raw
        .type _syscall_hook_trampoline_raw, @function
_syscall_hook_trampoline_raw:
        .cfi_startproc
        // GAS correctly put these in CIE as long as they
        // appears right after .cfi_startproc
        .cfi_return_column 32 // pc
        SAME_VALUE_X_NO8_NO15
        SAME_VALUE_ALL_Q
        // We define CFA as the value of the stack pointer when we enter this function
        // as specified in aadwarf64.
        // Since we aren't using the caller stack, none of the registers
        // we save will be in the CFA...
        .cfi_def_cfa sp, 0
        REG_AT_REG_OFFSET(0x20 /* pc */, 30, 16)
        REG_AT_REG_OFFSET(0x0f /* x15 */, 8,
                          (stub_scratch_2 - preload_thread_locals) | 0x80, 0)
        REG_AT_REG_OFFSET(0x1e /* x30 */, 8,
                          (stub_scratch_2 - preload_thread_locals + 8) | 0x80, 0)
        // x8 = x8 - preload_thread_locals
        // The last byte of the signed number LEB128 contains the top 4 bits
        // from the 32bit negative number (obtained using the shifted 0xF mask)
        // and 3 bits of leading ones above it (the `or`ing of the `0x70`).
        // The top bit of the byte is 0 signaling the end of the LEB128 encoding.
        .cfi_escape     0x16, /* DW_CFA_val_expression */                       \
                        0x08, /* x8 */                                          \
                        0x06, /* length 6 */                                    \
                        0x78, /* DW_OP_breg8 */                                 \
                        ((-preload_thread_locals) & 0x7F) | 0x80,               \
                        ((-preload_thread_locals) & (0x7F << 7)) >> 7 | 0x80,   \
                        ((-preload_thread_locals) & (0x7F << 14)) >> 14 | 0x80, \
                        ((-preload_thread_locals) & (0x7F << 21)) >> 21 | 0x80, \
                        ((-preload_thread_locals) & ( 0xF << 28)) >> 28 | 0x70
        // old gcc version doesn't want to encode bti
        // unless we specify armv8.5-a even though this was in the nop space.
        .inst   0xd503245f // bti     c
        mov     x15, preload_thread_locals
        // Stash away x30 so that we can have two registers to use again
        // we can't use stub_scratch_2 since we might overwrite the data there
        str     x30, [x15, stub_scratch_1 - preload_thread_locals]
        .cfi_escape     0x10, /* DW_CFA_expression */   \
                        0x20, /* pc */                  \
                        0x08, /* length 8 */            \
                        DW_OP_CONST4U(stub_scratch_1),  \
                        0x06, /* DW_OP_deref */         \
                        0x23, /* DW_OP_plus_uconst */   \
                        16
        // Move the register stash region from
        // `x8 + stub_scratch_2 - preload_thread_locals`
        // (i.e. `stub_scratch_2 + original_x8`) to the start of `stub_scratch_2`
        // Do it in the forward order since we know x8 >= stub_scratch_2
        ldr     x30, [x8, stub_scratch_2 - preload_thread_locals]
        str     x30, [x15, stub_scratch_2 - preload_thread_locals]
        ldr     x30, [x8, stub_scratch_2 - preload_thread_locals + 8]
        str     x30, [x15, stub_scratch_2 - preload_thread_locals + 8]
        // Restore x8
        movk    x8, 0, lsl 16
        .cfi_same_value x8
        REG_AT_ADDR32(0x0f /* x15 */, stub_scratch_2)
        REG_AT_ADDR32(0x1e /* x30 */, stub_scratch_2 + 8)

        cmp     x8, 0xdc // SYS_clone
        .cfi_remember_state
        b.eq    .Lfallback_rawsyscall

        ldr     w30, [x15, alt_stack_nesting_level - preload_thread_locals]
        cmp     w30, 0
        add     w30, w30, 1
        str     w30, [x15, alt_stack_nesting_level - preload_thread_locals]

        b.ne    .Lnest_syscall_hook_trampoline_raw
        ldr     x30, [x15, syscallbuf_stub_alt_stack - preload_thread_locals]
        sub     x30, x30, 48
        b       .Lstackset_syscall_hook_trampoline_raw
.Lnest_syscall_hook_trampoline_raw:
        sub     x30, sp, 48
.Lstackset_syscall_hook_trampoline_raw:
        // Now x30 points to the new stack with 48 bytes of space allocated

        // Move sp into a normal register. Otherwise we can't store it
        mov     x15, sp
        // Save sp to new stack.
        str     x15, [x30, 16]
        mov     sp, x30
        REG_AT_REG_OFFSET(0x1f /* sp */, 31, 16)
        .cfi_escape     0x0f, /* DW_CFA_def_cfa_expression */   \
                        0x03, /* 3 bytes follow */              \
                        0x8f, /* DW_OP_breg31 */                \
                        16,                                     \
                        0x06 /* DW_OP_deref */
        // sp is switched, x15 and x30 are free to use
        // [stub_scratch_1] holds the stub address

        // Now we need to construct the stack frame, with everything
        // in the scratch area copied over so that we can nest again.
        mov     x15, preload_thread_locals
        // load runtime stub address
        ldr     x30, [x15, stub_scratch_1 - preload_thread_locals]
        // save stub return address
        str     x30, [sp]
        // load syscall return address
        ldr     x30, [x30, 16]
        str     x30, [sp, 8]
        ldr     x30, [x15, stub_scratch_2 - preload_thread_locals]
        str     x30, [sp, 24]
        ldr     x30, [x15, stub_scratch_2 - preload_thread_locals + 8]
        str     x30, [sp, 32]

        // stackframe layout
        // 32: original x30
        // 24: original x15
        // 16: original sp
        // 8: return address to syscall
        // 0: return address to stub
        REG_AT_REG_OFFSET(0x20 /* pc */, 31, 8)
        REG_AT_REG_OFFSET(0x0f /* x15 */, 31, 24)
        REG_AT_REG_OFFSET(0x1e /* x30 */, 31, 32)

        bl _syscall_hook_trampoline

/**
 * The _syscall_hook_trampoline restores all the registers to the previous values
 * (minus the register for syscall return value) so we just need to restore
 * the registers we’ve overwritten by the end of the stack switch,
 * i.e. x15 , x30 and sp.
 * x15 and x30 will be restored when we get back to the stub
 * so we don’t need to restore them here but we do need to copy their values
 * to stub_scratch_2 again so that the stub can restore them
 * (since without a valid stack that is still the only memory
 * we can use to restore things).
 * We also need to store the return address to stub_scratch_1
 * since that’ll help rr with setting breakpoint.
 */

        movz    x15, #:abs_g1:stub_scratch_2 // assume 32bit address
        movk    x15, #:abs_g0_nc:stub_scratch_2
        ldr     x30, [sp, 24] // x15
        str     x30, [x15]
        ldr     x30, [sp, 32] // x30
        str     x30, [x15, 8]
        REG_AT_ADDR32(0x0f /* x15 */, stub_scratch_2)
        REG_AT_ADDR32(0x1e /* x30 */, stub_scratch_2 + 8)
        ldr     x30, [sp, 8] // syscall return address
        // tell rr breakpoint handling where we are going
        str     x30, [x15, stub_scratch_1 - stub_scratch_2]
        REG_AT_ADDR32(0x20 /* pc */, stub_scratch_1)
        ldr     x30, [sp] // stub return address
        ldr     x15, [sp, 16] // sp
        mov     sp, x15
        .cfi_restore sp
        .cfi_def_cfa sp, 0
        movz    x15, #:abs_g1:stub_scratch_2 // assume 32bit address
        movk    x15, #:abs_g0_nc:stub_scratch_2
_syscallbuf_final_exit_instruction:
        ret

.Lfallback_rawsyscall:
        .cfi_restore_state
        // Must not touch sp in this branch.
        // Use x15 to remember the return address since we are only copying
        // the first two elements of stub_scratch_2 for the child.
        ldr     x15, [x15, stub_scratch_1 - preload_thread_locals]
        REG_AT_REG_OFFSET(0x20 /* pc */, 15, 16)
        mov     x30, 0x70000000 // RR_PAGE_SYSCALL_TRACED
        blr     x30
        // stub_scratch_2 content is maintained by rr
        // we need to put the syscall return address in stub_scratch_1
        movz    x30, #:abs_g1:stub_scratch_2 // assume 32bit address
        movk    x30, #:abs_g0_nc:stub_scratch_2
        str     x15, [x30, 16] // stash away stub address
        ldr     x15, [x15, 16] // syscall return address
        .cfi_register 32, x15
        str     x15, [x30, stub_scratch_1 - stub_scratch_2]
        REG_AT_ADDR32(0x20 /* pc */, stub_scratch_1)
        mov     x15, x30
        ldr     x30, [x15, 16]
        b       _syscallbuf_final_exit_instruction

        .cfi_endproc
        .size _syscall_hook_trampoline_raw, .-_syscall_hook_trampoline_raw

#endif /* __aarch64__ */

        .section .note.GNU-stack,"",@progbits
