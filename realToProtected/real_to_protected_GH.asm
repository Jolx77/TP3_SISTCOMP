   
   ;PUSH_ADX
   push %ax
   push %bx
   push %cx
   push %dx
   ;PUSH_ADX end

   mov $0x0600, %ax
   mov $0x7, %bh
   mov $0x0, %cx
   mov $0x184f, %dx
   int $0x10

   ;POP_DAX
   pop %dx
   pop %cx
   pop %bx
   pop %ax
   ;POP_DAX end

   ;PROTECTED_MODE 
   .equ CODE_SEG
   .equ DATA_SEG, gdt_data - gdt_s

   lgdt gdt_descript

   mov %cr0, %eax
   orl $0x1, %eax
   mov %eax, 