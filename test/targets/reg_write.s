.global main

.section .data
hex_format:         .asciz "%#x"
float_format:       .asciz "%.2f"
long_float_format:  .asciz "%.2Lf"

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

    trap
    
    # Print contents of rsi
    leaq    hex_format(%rip), %rdi
    movq    $0, %rax
    call    printf@plt
    movq    $0, %rdi
    call    fflush@plt

    trap

    # Print contents of mm0
    movq    %mm0, %rsi
    leaq     hex_format(%rip), %rdi
    movq    $0, %rax
    call    printf@plt
    movq    $0, %rdi
    call    fflush@plt

    trap

    # Print contents of xmm0
    leaq    float_format(%rip), %rdi
    movq    $1, %rax
    call    printf@plt
    movq    $0, %rdi
    call    fflush@plt

    trap

    # Print contents of st0
    subq    $16, %rsp
    fstpt   (%rsp)
    leaq    long_float_format(%rip), %rdi
    movq    $0, %rax
    call    printf@plt
    movq    $0, %rdi
    call    fflush@plt
    addq    $16, %rsp

    trap

    popq    %rbp
    movq    $0, %rax
    ret 