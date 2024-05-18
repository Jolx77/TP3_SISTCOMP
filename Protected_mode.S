.equ CODE_SEG, gdt_code - gdt_start
.equ DATA_SEG_RW, gdt_data_rw - gdt_start

.code16

protected_mode_start:
   cli
   lgdt gdt_descriptor

   /* Configurar el manejador de interrupciones para la excepción GPF */
   lidt idt_descriptor

   mov %cr0, %eax
   orl $0x1, %eax
   mov %eax, %cr0 

   ljmp $CODE_SEG, $protected_mode

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
    gdt_data_rw:
        .word 0xffff
        .word 0x0
        .byte 0x0
        .byte 0b10010010 /* lectura/escritura */
        .byte 0b11001111
        .byte 0x0
gdt_end:

gdt_descriptor:
    .word gdt_end - gdt_start
    .long gdt_start

/* Tabla de Descriptores de Interrupción (IDT) */
idt_start:
    /* Rellenar las primeras 12 entradas con un manejador de interrupciones genérico o vacío */
    .rept 0x0D
        .quad 0
    .endr

    /* Entrada para la excepción GPF (interrupción 13) */
    .word gpf_handler
    .word CODE_SEG
    .byte 0
    .byte 0b10001110
    .word 0
idt_end:

idt_descriptor:
    .word idt_end - idt_start
    .long idt_start


.code32
protected_mode:

    call print_message

    mov $DATA_SEG_RW, %ax /*cargamos en ax el valor de DATA_SEG y se lo cargamos a todos los registros de segmentos */
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss

looop:
    jmp looop

/* Manejador de interrupciones para la excepción GPF */
gpf_handler:
    pusha
    mov $gpf_message, %ecx
    call print_message_gpf
    popa
    jmp looop
    

/* Print message on VGA */
print_message:
    mov $message, %ecx                  /* Load the address of the message into ECX */
    mov vga, %eax                       /* Load the address of the VGA buffer into EAX */
    
    /* Calculate VGA memory address */
    mov $160, %edx
    mul %edx
    lea 0xb8000(%eax), %edx
    mov $0x0f, %ah 
lup:
    mov (%ecx), %al                     /* Load the character from the message into AL */
    cmp $0, %al                         /* Check for the end of the message */
    je thiistheend
    
    mov %ax, (%edx)                     /* Write the character to the VGA buffer */
    
    /* Move to the next character in the message and VGA buffer */
    add $1, %ecx
    add $2, %edx
    jmp lup
thiistheend:
    ret

/* Print message on VGA */
print_message_gpf:
    mov $gpf_message, %ecx                  /* Load the address of the message into ECX */
    mov vga, %eax                           /* Load the address of the VGA buffer into EAX */
    
    /* Calculate VGA memory address */
    mov $160, %edx
    mul %edx
    add $160, %eax                          /* Move to the next line */
    lea 0xb8000(%eax), %edx
    mov $0x0f, %ah 
loop:
    mov (%ecx), %al                         /* Load the character from the message into AL */
    cmp $0, %al                             /* Check for the end of the message */
    je end
    
    mov %ax, (%edx)                         /* Write the character to the VGA buffer */
    
    /* Move to the next character in the message and VGA buffer */
    add $1, %ecx
    add $2, %edx
    jmp loop
end:
    ret

/* Clear VGA memory */
clear_vga:
    mov $0xb8000, %edi /* Start of VGA memory */
    mov $0x0f20, %ax   /* Attribute byte (0x0f) followed by space character (0x20) */
    mov $4000, %ecx    /* VGA memory is 4000 words long */
    rep stosw          /* Repeat STOSW ECX times */
    ret


/* Message to be printed on VGA */
message:
    .asciz "P-mode"

/* Mensaje a imprimir cuando se produce una excepción GPF */
gpf_message:
    .asciz "GPF"
    
/* VGA buffer address */
vga:
    .long 10
