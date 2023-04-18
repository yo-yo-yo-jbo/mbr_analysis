[bits 16]
[org 0x7C00]

;
; Constants
;
CLOCK_INTERUPT_NUMBER equ 8

;
; Start of "bootloader" code
;
routine_start:

	; Clear the direction flag (just in case)
	cld
	
	; Prepare setting up by preventing interrupts
	cli
	
	; Back up the interrupt entry
	mov si, CLOCK_INTERUPT_NUMBER * 4
	mov di, data_original_isr
	movsd 
	
	; Set DI to point to the entry for INT 8 (clock)
	mov di, CLOCK_INTERUPT_NUMBER * 4
	
	; Write IP of the new entry and increase DI accordingly
	mov ax, routine_timer_hook
	stosw
	
	; Write CS of the new entry and increase DI accordingly
	xor ax, ax
	stosw
	
	; Write a prefix message
	mov si, data_prefix_msg
	call routine_print_msg
	
	; Allow interrupts
	sti

	; Hang forever
	jmp $

;
; Routine: timer_hook
; Assumes:
;   * Being called as an interrupt service routine
;   * Returns: Nothing
;
routine_timer_hook:

	; Print the message (SI points to the message)
	mov si, data_hook_msg
	call routine_print_msg
	
	; Jump to the original interrupt
	mov si, data_original_isr
	lodsw
	mov bx, ax
	lodsw
	push ax
	push bx
	retf

;
; Routine: print_msg
; Assumes:
;   * SI register points to a NUL terminated string to print
;   * Direction flag is clear
; Returns: Nothing
;
routine_print_msg:

	; Load the next character to AL and increase SI
	lodsb
	
	; If we hit a NUL terminator - return
	test al, al
	jnz .non_nul
	ret
	
.non_nul:

	; Print the character in AL and move to the next character
	call routine_print_char
	jmp routine_print_msg

;
; Routine: print_char
; Assumes:
;   * AL register points to the ASCII character to print out
; Returns: Nothing
;
routine_print_char:

	; Prepares service interrupt 0x10 with AH=0x0E (teletype output)
	mov ah, 0x0e
	
	; Character characteristics - page 0 and gray foreground
	mov bx, 0x0007
	
	; Call interrupt and return
	int 0x10
	ret

;
; Data
;
data_hook_msg:
	db "lolhax :)", 13, 10, 0
data_prefix_msg:
	db "Hook installed!", 13, 10, 0
data_original_isr:
	dw 0, 0

;
; Fill sector data with zeros and last two bytes to be 0x55, 0xAA
;
times 510 - ($ - $$) db 0
dw 0xaa55
