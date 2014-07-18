        .text



        .p2align 4,,15
        .globl  set_xmm0
        .type   set_xmm0, @function
set_xmm0:
        .cfi_startproc
        movl    4(%esp),%eax
        movaps  (%eax),%xmm0
        ret
        .cfi_endproc
        .size   set_xmm0, .-set_xmm0



        .p2align 4,,15
        .globl  get_xmm0
        .type   get_xmm0, @function
get_xmm0:
        .cfi_startproc
        movl    4(%esp),%eax
        movaps  %xmm0,(%eax)
        ret
        .cfi_endproc
        .size   get_xmm0, .-get_xmm0



.section        .note.GNU-stack,"",@progbits
