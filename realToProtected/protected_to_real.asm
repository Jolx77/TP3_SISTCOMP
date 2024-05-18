; Switch from protected mode to real mode
; Assumes DS points to a valid descriptor in the GDT with base 0 and limit 0xFFFFF

cli                    ; Disable interrupts
mov eax, cr0           ; Move the contents of CR0 into EAX
and ax, 0xFFFE         ; Clear the PE bit (bit 0) of EAX
mov cr0, eax           ; Move the contents of EAX back into CR0
jmp 0x8:flush          ; Far jump to flush the CPU pipeline

flush:
mov ax, 0x10           ; Value of the data segment descriptor
mov ds, ax             ; Load DS with the value
mov es, ax             ; Load ES with the value
mov fs, ax             ; Load FS with the value
mov gs, ax             ; Load GS with the value
mov ss, ax             ; Load SS with the value

sti 				   ; Enable interruptions

; Now in real mode