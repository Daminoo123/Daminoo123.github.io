---
layout: post
title:  "R0bob1rd Challenge Write-Up"
date:   2025-06-09 14:45:00 -0500
categories: ctf pwn exploit
permalink: /certifications/2025/06/16/CRTP-REVIEW/
---

This document details the process of exploiting the `r0bob1rd` binary to achieve a remote shell. The exploit leverages an Out-of-Bounds read to leak a `libc` address, followed by a Format String Bug to hijack the `__stack_chk_fail` function, ultimately triggering a `one_gadget` for code execution.

---

## **1. Initial Analysis**

First, we perform static analysis on the provided binary to understand its properties and security mitigations.

### **File Properties**

The binary is a standard 64-bit Linux executable and is not stripped, meaning symbol names are intact, which simplifies reverse engineering.

```bash
$ file r0bob1rd
r0bob1rd: ELF 64-bit LSB executable, x86-64, ... dynamically linked, ... not stripped

A review of the security flags reveals our potential attack surface.

$ checksec --file=r0bob1rd
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified Fortifiable FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   RW-RUNPATH   83 Symbols      No      0         2             r0bob1rd
No PIE: Position-Independent Executable is disabled. This is a significant advantage, as the binary's code and global data sections will be loaded at the same fixed memory address every time.

Partial RELRO: The Global Offset Table (GOT) is writable. This is the key vulnerability that will allow us to overwrite function pointers.

NX enabled: The stack and heap are non-executable, preventing simple shellcode injection.

Canary found: Stack canaries are enabled. Instead of bypassing this, our strategy will be to abuse the failure-checking mechanism itself

2. Vulnerability Analysis
Decompiling the binary in Ghidra reveals two key vulnerabilities within the operation() function:
![Final Exploit Execution]({{ '/imgs/robobird/ghidra.png' | relative_url }})

Out-of-Bounds (OOB) Read: When selecting a bird, the program reads an integer but does not validate that it is within the expected range. By providing a negative index, we can read memory locations before the start of the robobirdNames global variable, which is located near the GOT, allowing us to leak libc function addresses.

Format String Bug (FSB): When providing the bird's description, the program uses printf(user_controlled_buffer). This allows an attacker to inject format string specifiers like %n to write to arbitrary memory locations.

3. Exploit Strategy
The plan is to weaponize the program's own security features against itself.

Leak libc Address
Use the OOB read vulnerability with index -16 to leak the runtime address of the puts function from its GOT entry. This will defeat ASLR for the libc library.

Calculate one_gadget Address
Using the leaked puts address, calculate the libc base. From there, find the runtime address of a one_gadget—a single address in libc that, when called, spawns a shell.

Overwrite __stack_chk_fail GOT Entry
Use the Format String Bug to overwrite the GOT entry for the __stack_chk_fail function. We will replace its address with the address of our chosen one_gadget.

Trigger the Hijack
Intentionally cause a buffer overflow when providing the description. This will corrupt the stack canary. When the function returns, the canary check will fail, forcing the program to call the hijacked __stack_chk_fail function, which now points to our one_gadget.

4. Step-by-Step Implementation
A. Information Gathering
Calculate the Leak Index for puts:

css
Copier
Modifier
puts@got.plt      = 0x602020  
robobirdNames     = 0x6020a0  
(0x602020 - 0x6020a0) / 8 = -16
Find libc Offsets and Gadgets:

bash
$ readelf -s ./glibc/libc.so.6 | grep ' puts@'
# Offset: 0x084420
![Final Exploit Execution]({{ '/imgs/robobird/gadgets.png' | relative_url }})
$ one_gadget ./glibc/libc.so.6
# Choose: 0xe3b01
Gadget Verification in GDB

![Final Exploit Execution]({{ '/imgs/robobird/gadgets2.png' | relative_url }})
Target GOT Address for Overwrite:

bash
$ objdump -R r0bob1rd | grep '__stack_chk_fail'
0x602018 R_X86_64_JUMP_SLOT  __stack_chk_fail@GLIBC_2.4
Format String Offset:

Stack offset for our input is 16.

 Final Exploit Script:


![Final Exploit Execution]({{ '/imgs/robobird/solver.png' | relative_url }})

![Final Exploit Execution]({{ '/imgs/robobird/pwn2.png' | relative_url }})