        .text



        .macro DEFINE_XMM reg

        .p2align 4,,15
        .globl  set_xmm\reg
        .type   set_xmm\reg, @function
set_xmm\reg:
        .cfi_startproc
        movl    4(%esp),%eax
        movaps  (%eax),%xmm\reg
        ret
        .cfi_endproc
        .size   set_xmm\reg, .-set_xmm\reg
        .p2align 4,,15
        .globl  get_xmm\reg
        .type   get_xmm\reg, @function
get_xmm\reg:
        .cfi_startproc
        movl    4(%esp),%eax
        movaps  %xmm\reg,(%eax)
        ret
        .cfi_endproc
        .size   get_xmm\reg, .-get_xmm\reg

        .endm

        DEFINE_XMM 0
        DEFINE_XMM 1
        DEFINE_XMM 2
        DEFINE_XMM 3
        DEFINE_XMM 4
        DEFINE_XMM 5
        DEFINE_XMM 6
        DEFINE_XMM 7



        .macro DEFINE_ST reg

        .p2align 4,,15
        .globl  set_st\reg
        .type   set_st\reg, @function
set_st\reg:
        .cfi_startproc
        movl    4(%esp),%eax
        finit
        fldt    (%eax)
        fst     %st(\reg)
        ret
        .cfi_endproc
        .size   set_st\reg, .-set_st\reg
        .p2align 4,,15
        .globl  get_st\reg
        .type   get_st\reg, @function
get_st\reg:
        .cfi_startproc
        movl    4(%esp),%eax
        fld     %st(\reg)
        fstpt   (%eax)
        ret
        .cfi_endproc
        .size   get_st\reg, .-get_st\reg

        .endm

        DEFINE_ST 0
        DEFINE_ST 1
        DEFINE_ST 2
        DEFINE_ST 3
        DEFINE_ST 4
        DEFINE_ST 5
        DEFINE_ST 6

        .p2align 4,,15
        .globl  set_st7
        .type   set_st7, @function
set_st7:
        .cfi_startproc
        movl    4(%esp),%eax
        fldt    (%eax)
        fst     %st(7)
        ret
        .cfi_endproc
        .size   set_st7, .-set_st7
        .p2align 4,,15
        .globl  get_st7
        .type   get_st7, @function
get_st7:
        .cfi_startproc
        movl    4(%esp),%eax
        fdecstp
        fstpt   (%eax)
        ret
        .cfi_endproc
        .size   get_st7, .-get_st7



.section        .note.GNU-stack,"",@progbits
