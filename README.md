# MBR payloads

In recent years, we've seen interesting MBR payloads, ranging from [ransomware](https://www.microsoft.com/en-us/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/) to generic malware.  
While new technologies ([UEFI](https://en.wikipedia.org/wiki/UEFI)) makes MBR payloads obsolete, the sad reality is that old BIOS-style boot sequences are still commonly used.  
This blogpost discusses MBR payloads - I really like old real mode Assembly, so the MBR payloads are a nice opportunity. Let's go!

## What is an MBR
In the old days before UEFI, the first code to run was the [BIOS](https://en.wikipedia.org/wiki/BIOS), which is a piece of software (firmware).
The BIOS had several responsibilities, most notable [Power-On-Self-Test (POST)](https://en.wikipedia.org/wiki/Power-on_self-test), which verifies the CPU registers, BIOS integrity, RAM, DMA, timers etc. BIOS also performs several setup and configurations for booting, including configuring PCI setting up software interrupts.
After all the testing and configuration done, the BIOS will compare all storage devices, compare to its own boot configuration and try to find the first *bootable* device. How does a BIOS know that a device is bootable? By *magic* :)  
The BIOS reads the first sector (512 bytes) of the device and compares the last 2 bytes to the bytes `\x55\xAA` - if they're there then: that sector (512 bytes) is loaded to address `0x7C00`. Note this is done in Intel real mode, which means that:
1. Memory is segmented - we touch physical RAM with segments, done with special registers (`cs`, `ds`, `es`, `ss`).
2. We usually refer to 16-bit registers (e.g. `ax`, `bx` and so on).
Well, that 512 byte sector ending with `\x55\xAA` is referred as the `MBR`, which stands for `Master Boot Record`.

Normally, the `MBR` runs code that reads further chunks from the bootable disk and loads a second stage `bootloader` (such as `grub2` or `winload`), which is responsible of setting up virtual memory (unless we're talking about a very old OS) and loading an eventual kernel from the disk.

## Experiment - viewing your MBR
To support both UEFI and old MBR, Windows sets up the MBR. You can dump it even with Python (run elevated):
```python
import binascii

with open(r'\\.\physicaldrive0', 'rb') as f:
    c = f.read(512)

print(binascii.hexlify(c))
```
Note how your MBR ends with `55aa`.  
For Linux, you could read the first `512` bytes from `/dev/sda` (or whatever boot device you used) similarly.

## What does the MBR do?
As I mentioned, the `MBR` is mostly responsible for loading further code from disk, which loads *more* data from disk, which will eventually set up memory management and switch out of real mode to a 32/64 addressing mode. The number of stages depend on the bootloader - for example, `grub2` is sometimes referred to as a "2.5 stage bootloader", due to how it works:
- Stage 1: `boot.img` (its `MBR`) is loaded by the BIOS, from the first sector (512 bytes).
- Stage 1.5: `boot.img` loads `core.img` from disk (specifically, between the `MBR` and the first disk partition).
- Stage 2.5 `core.img` (which was loaded by the `MBR`) loads `/boot/grub/i386-pc/normal.mod`.
- After `normal.mod` is loaded, it parses `/boot/grub/grub.cfg` and acts according to the grub configuration file.

Note this requires parsing a filesystem, and specifically - *loading data from disk*. This is commonly achieved by *software interrupts*.  
Remember I mentioned the BIOS sets us software interrupts? This is where they come handy. There are many interesting interrupts that can be used by bootloaders.  
The best documentation I remember was [Ralf Brown's Interrupt List](https://www.ctyme.com/rbrown.htm). Common interrupts used by bootloaders include:
- Disk access - [int 13h](http://www.ctyme.com/intr/rb-0607.htm) - to read more data from the disk.
- Read keyboard input - [int 16h](http://www.ctyme.com/intr/rb-1754.htm).
- Write to screen - [int 10h](http://www.ctyme.com/intr/rb-0099.htm).

## Experiment - calling interrupts
You can code your first "bootloader" with ease. I tend to use [NASM](https://www.nasm.us/) (aka the best assembler in the world), but you can use whatever you like.  
The only things to keep in mind are:
1. Assemble your program to 16-bit real mode, raw format.
2. Your program code should start at address `0x7C00`.
3. Your program should only rely on 512 bytes being loaded, and the first two bytes must be `\x55\xAA`.

In our "bootloader" (I am not doing justice to bootloaders here, but whatever) we will be presenting a "Hello boot" message and hang in an endless loop. Note we must hang, there's no "exit" instruction!
Let's code it:

```assembly
[bits 16]
[org 0x7C00]

;
; Start of "bootloader" code
;
routine_start:

	; Clear the direction flag (just in case)
	cld

	; Print the message (SI points to the message)
	mov si, data_my_msg
	call routine_print_msg
	
	; Hang forever
	jmp $

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
data_my_msg:
	db "Hello b00t", 0

;
; Fill sector data with zeros and last two bytes to be 0x55, 0xAA
;
times 510 - ($ - $$) db 0
dw 0xaa55
```
This seems a lot to unpack, but not really:
- First two directives make sure we're using 16-bit real mode in address `0x7C00`.
- In `routine_start` we simply clear the direction flag (I discussed that flag [in a previous blogpost](https://github.com/yo-yo-yo-jbo/msf_shellcode_analysis/)) and load the message we want to print to the `si` register. Then we call `routine_print_msg` (which prints the message at `si` to the screen) and then hang (`jmp $` simply jumps to itself).
- In `routine_print_msg` we simply create a loop that loads the next character from `si` to `al` and increases `si`, checks if `al` is zero (NUL character) - if it is, we return, otherwise we call `routine_print_char` and loop back to the next character processing.
- Finally, in `routine_print_char` we call `int 10h` with `ah=0x0e` (teletype printing) and make sure we print to page 0 with a gray foreground.
- The `data_my_msg` is a data label that holds the message we'd like to print.
- The end of our bootloader fills `510 - (size of code and data)` with zeros, and then writes `\x55\xAA` (note it's Little Endian so we define a WORD with `dw` to be `0xAA55`).

Assembling is easy with NASM:
```shell
nasm -fbin -oboot.img boot.asm
```
You can debug this "bootloader" with appropriate emulators like `qemu` or [Bochs](https://bochs.sourceforge.io/) (my personal favorite) - simply attach the `boot.img` file you assembled to a virtual 1.44Mb Floppy Disk and boot from there. You should see our message appearing!

## Experiment - hooking interrupts
Interrupts are saved in an `Interupt Vector Table (IVT)` starting at address 0, with each entry having a size of 2 WORDS (so, 4 byttes). This means that the entire region of `0x0000 - 0x03FF` is reserved for that table.  
Why does every entry have 2 WORDs? Because every entry is a `FAR call`. Do you remember I said our memory is segmented? Our code doesn't really run from the `ip` register - it runs from `cs:ip`. The real address our code runs in is `0x10 * CS + IP`. A call that changes both `cs` and `ip` is called a `FAR Call`, and as the name suggests - can be used to start running code in a region far from our own.  
Let's use this knowledge to hook an interrupt routine! [Interrupt 8](http://www.ctyme.com/intr/int-08.htm) is the *timer routine* and will be called 18.2 times every second. We can change it to print something instead by writing to address `8 * 4 = 0x0020` - which points to the 9th entry in the `IVT`.  
Since we run between `0x7C00 - 0x7DFF`, we can easily just set `cs` to be 0 in our new entry and `ip` to be our address:

```assembly
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
```
Let's examine what we've done:
- `CLOCK_INTERUPT_NUMBER equ 8` is NASM-speak for a C-style `#define` - NASM will simply search and replace it when assembling.
- In `routine_start`, when setting up the interrupt hook, we use `cli` to clear the interrupt flag. This is important, as setting up the clock interrupt is not atomic and interrupts can (and probably will occur) during this time.
- We back up the original clock interrupt in `data_original_isr` by copying the data from `si` (which points to address `0x20`) to `di` using the `movsd` instruction. That instruction copies 4 bytes at once - hurray!
- We then use a similar trick - this time `di` points to the interrupt entry (`0x20`) and we store `ax` there with `stosw` - once for the `ip` register (which points to our `routine_timer_hook` routine) and once for `cs` (which will get 0 using self-`xor`ing).
- After printing a message, we use `sti` to enable interrupts again, and then hang forever.
- The `routine_timer_hook` routine is quite simple: it prints a message and then calls the original routine that was saved in `data_original_isr`, by pushing the old entry's `cs` and `ip` registers to the stack and then performing `retf`, which pops those two values into `cs:ip`.

Note that hooking the interrupt vector table was used in the past extensively for bootkit purposes.

## Exercise - analyzing a ransomware MBR payload
As a final exercise, let's completely analyze the destructive malware [described in Microsoft's blogpost](https://www.microsoft.com/en-us/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/). I will analyze the file [a196c6b8ffcb97ffb276d04f354696e2391311db3841ae16c8c9f56f36a38e92](https://www.virustotal.com/gui/file/a196c6b8ffcb97ffb276d04f354696e2391311db3841ae16c8c9f56f36a38e92/).  
Extracting the MBR from IDA was easy - simply looking for the malicious strings shows the following pseudo code part in `sub_403B60`:
```c
HANDLE hFile;
hFile = CreateFileW(L"\\\\.\\PhysicalDrive0", 0x10000000, 3, NULL, 3, 0, NULL);
WriteFile(hFile, g_mbr_buf, 0x200, NULL, NULL);
CloseHandle(hFile);
```

As you can see, we're *writing* to `\\.\PhysicalDrive0`, which points to the `MBR`. The `0x200` is the 512 bytes of the new MBR - neat!  
Let's disassemble the buffer written, rebasing it to address `0x7C00`:

```assembly
```
