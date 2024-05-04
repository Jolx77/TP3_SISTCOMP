/* Bloque 1: Definición de los segmentos de código y datos */
.equ CODE_SEG, 8  // Define el segmento de código como 8
.equ DATA_SEG, gdt_data - gdt_start  // Define el segmento de datos como la diferencia entre gdt_data y gdt_start

/* Bloque 2: Carga de la GDT en la memoria */
lgdt gdt_descriptor  // Le dice al procesador dónde está nuestra Tabla Global de Descriptores (GDT) en la memoria

/* Bloque 3: Entrada en modo protegido */
mov %cr0, %eax  // Mueve el contenido del Registro de Control 0 (CR0) a EAX
orl $0x1, %eax  // Establece el bit PE (Protección Habilitada) en CR0
mov %eax, %cr0  // Mueve el contenido de EAX a CR0
ljmp $CODE_SEG, $protected_mode  // Salta a la etiqueta protected_mode en el segmento de código

gdt_start:  // Inicio de la GDT
gdt_null:   // Descriptor nulo, requerido por la arquitectura x86
    .long 0x0
    .long 0x0

gdt_code:   // Descriptor del segmento de código
    .word 0xffff  // Límite del segmento (tamaño)
    .word 0x0     // Base del segmento (dirección de inicio)
    .byte 0x0     // Base (parte media)
    .byte 0b10011010  // Flags del segmento (presente, descriptor de segmento, nivel de privilegio, ejecutable, dirección de crecimiento)
    .byte 0b11001111  // Límite (parte alta) y flags (tamaño y granularidad)
    .byte 0x0     // Base (parte alta)

gdt_data:   // Descriptor del segmento de datos
    .word 0xffff  // Límite del segmento (tamaño)
    .word 0x0     // Base del segmento (dirección de inicio)
    .byte 0x0     // Base (parte media)
    .byte 0b10010010  // Flags del segmento (presente, descriptor de segmento, nivel de privilegio, no ejecutable, dirección de crecimiento)
    .byte 0b11001111  // Límite (parte alta) y flags (tamaño y granularidad)
    .byte 0x0     // Base (parte alta)

gdt_end:    // Fin de la GDT
gdt_descriptor:  // Etiqueta para el descriptor de la GDT
    .word gdt_end - gdt_start  // Define el tamaño de la GDT
    .long gdt_start  // Define la dirección de inicio de la GDT
vga_current_line:  // Etiqueta para la línea actual de la VGA
    .long 0  // Inicializa la línea actual de la VGA en 0
.code32
protected_mode:
    /* Setup the other segments.
     * Those movs are mandatory because they update the descriptor cache:
     * http://wiki.osdev.org/Descriptor_Cache
     */
    mov $DATA_SEG, %ax  // Mueve el valor de DATA_SEG a AX
    mov %ax, %ds  // Mueve el contenido de AX al segmento de datos
    mov %ax, %es  // Mueve el contenido de AX a ES
    mov %ax, %fs  // Mueve el contenido de AX a FS
    mov %ax, %gs  // Mueve el contenido de AX a GS
    mov %ax, %ss  // Mueve el contenido de AX a SS
    /* TODO detect the last memory address available properly.
     * It depends on how much RAM we have.
     */
    mov $0X7000, %ebp  // Mueve el valor 0x7000 a EBP
    mov %ebp, %esp  // Mueve el contenido de EBP a ESP
.endm

/* Setup the first Page Directory entry, which gives us a 4MB(2^10 * 2^12) memory region.
 * The memory region starts at 0, and the virtual address and physical address are identical.
 * 
 * The currently executing code is inside that range, or else we'd jump somewhere and die.
 */
.equ page_directory, __end_align_4k
.equ page_table, __end_align_4k + 0x1000