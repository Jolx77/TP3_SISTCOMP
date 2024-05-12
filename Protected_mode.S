.equ CODE_SEG, gdt_code - gdt_start
.equ DATA_SEG, gdt_data - gdt_start

.code16

gpf_handler:
    mov $gpf_message, %si
print_gpf_loop:
    lodsb
    or %al, %al
    jz done_gpf_print
    mov $0x0e, %ah
    xor %bh, %bh
    int $0x10
    jmp print_gpf_loop
done_gpf_print:
    jmp done_gpf_print  /* Bucle infinito */
gpf_message:
    .asciz "GPF!"

protected_mode_start:
   cli
   lidt idt_descriptor
   lgdt gdt_descriptor

   mov %cr0, %eax
   orl $0x1, %eax
   mov %eax, %cr0 

   ljmp $CODE_SEG, $protected_mode

protected_mode:

    mov $DATA_SEG, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss

    mov $0X7000, %esp
    mov $0x1234, %bx
    mov $0x5678, %cx
    mov %cx, %ds:(%bx)
    mov $protected_mode_message, %si
    
print_protected_mode_loop:
    lodsb
    or %al, %al
    jz done_protected_mode_print
    mov $0x0e, %ah
    xor %bh, %bh
    int $0x10
    jmp print_protected_mode_loop
done_protected_mode_print:

loop:
    jmp loop

protected_mode_message:
    .asciz "Protected Mode"

gdt_start:
    gdt_null:
        .long 0x0
        .long 0x0
    gdt_code:
        .word 0xffff
        .word 0x0
        .byte 0x0
        .byte 0b10011010
        .byte 0b11001111
        .byte 0x0
    gdt_data:
        .word 0xffff
        .word 0x0
        .byte 0x0
        .byte 0b10010000
        .byte 0b11001111
        .byte 0x0
gdt_end:

gdt_descriptor:
        .word gdt_end - gdt_start
        .long gdt_start

idt_start:
    .rept 1
        .long 0x0
        .long 0x0
    .endr
    idt_gpf:
        .word gpf_handler
        .word CODE_SEG
        .byte 0x0
        .byte 0b10001110
        .word 0x0
idt_end:

idt_descriptor:
    .word idt_end - idt_start
    .long idt_start
    