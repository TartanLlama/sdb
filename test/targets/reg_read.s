.global main

.section .data
my_double: .double 64.125

.section .text

.macro trap
    movq $62, %rax
    movq %r12, %rdi
    movq $5, %rsi
    syscall
.endm

main:
    push    %rbp
    movq    %rsp, %rbp

    # Get pid
    movq    $39, %rax
    syscall
    movq    %rax, %r12

    # Store to r13
    movq    $0xcafecafe, %r13
    trap

    # Store to r13b
    movb    $42, %r13b
    trap

    # Store to mm0
    movq    $0xba5eba11, %r13
    movq    %r13, %mm0
    trap

    # Store to xmm0
    movsd   my_double(%rip), %xmm0
    trap

    # Store to st0
    emms
    fldl     my_double(%rip)
    trap
    
    popq    %rbp
    movq    $0, %rax
    ret 