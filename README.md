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

## Experiment - viewing your Windows MBR
To support both UEFI and old MBR, Windows sets up the MBR. You can dump it even with Python (run elevated):
```python
import binascii

with open(r'\\.\physicaldrive0', 'rb') as f:
    c = f.read(512)

print(binascii.hexlify(c))
```
Note how your MBR ends with `55aa`.
