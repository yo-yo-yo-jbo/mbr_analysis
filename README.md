# Analysis of an MBR payload

In recent years, we've seen interesting MBR payloads, ranging from [ransomware](https://www.microsoft.com/en-us/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/) to generic malware.  
While new technologies ([UEFI](https://en.wikipedia.org/wiki/UEFI)) makes MBR payloads obsolete, the sad reality is that old BIOS-style boot sequences are still commonly used.  
This blogpost reverse engineers MBR payloads - I really like old real mode Assembly, so the MBR payloads are a nice opportunity. Let's go!

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
