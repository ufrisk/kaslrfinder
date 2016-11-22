KASLRfinder summary:
====================
KASLRfinder is a small utility that can be used to find where in memory the Windows 10 kernel and its drivers are loaded - despite the addresses being randomized by Kernel Address Space Layout Randomization (KASLR). 

The utility can be run as a normal program and requires no administrative privileges.

It works by timing the execution times of failed instructions inside Transactional Synchronization Extensions (TSX) block. TSX was first introduced in Haswell based CPUs; but got disabled due to problems. The TSX instructions are available on all Skylake CPUs. For more information please see the <a target="_blank" href="https://labs.bromium.com/2014/10/27/tsx-improves-timing-attacks-against-kaslr/">blog entry by Rafal Wojtczuk from Bromium Labs</a> or the <a target="_blank" href="https://www.blackhat.com/us-16/briefings.html#breaking-kernel-address-space-layout-randomization-kaslr-with-intel-tsx">Black Hat presentation by Yeongjin, Sangho, and Taesoo from Georgia Institute of Technology.</a>

Please also have a look at my blog entry, <a href="http://blog.frizk.net/2016/11/windows-10-kaslr-recovery-with-tsx.html">Windows 10 KASLR Recovery with TSX</a>, describing a bit more in-depth about KASLRfinder and how it works.

System Requirements:
====================
* Skylake based CPU or newer (some Haswells may work too)
* Windows 10 64-bit

Stability and Limitations:
==========================
* KASLRfinder is far from stable. It won't crash; but some times it will fail to find the memory addresses.
* KARLRfinder has only been tested on Windows 10 1607 / Skylake CPU.
* Feedback is appreciated; but I do not plan to officially support this utility.

Capabilities:
=============
KALRfinder is able to:
* Locate the kernel address within an error margin of 1MB.
* Locate a driver or module address exactly - using a signature based search.
* Generate new signatures based on user supplied memory addresses.

Examples:
=========
Search for the kernel base address within an error margin of 1MB:

* `kalrfinder.exe`

Search for the exact base address of the driver tcpip.sys (1607/November patches):

* `kaslrfinder.exe -sig 01809a0155800100`

Generate a signature for the driver loaded at: 0xFFFFF80878880000 with size: 0x0005D000:

* `kaslrfinder.exe -sigbase 0xFFFFF80878880000 -size 0x0005D000`

Find out what's wrong with the signature for a driver if it's not detected and the address is already known:

* `kaslrfinder.exe -sig 01809a015580010 -sigbase 0xFFFFF80878880000 -size 0x0005D000`

Signatures:
===========
The best way to find the addresses required to generate the signatures is by using pcileech. Just insert the pcileech kernel module into the target computer. Then use the wx64_driverinfo module.

If a signature is created and it won't work later on it may be because of changes in the signature itself, or errors in detecting it. If there are errors in detecting it try to run kaslrfinder specifying both the signature and the known based address and size to get the potential hint about whats wrong. Most times its recommended shortening the signature as much as possible to improve accuracy. If the signature is shortened enough false positives may occur though. If shortened it must be shortened in 2-byte (4-hex chars) decrements.

Sample Signatures:
==================
tcpip.sys - Windows 10 1607 - November 2016 - 10.0.14393.351: `01809a0155800100`

msrpc.sys - Windows 10 1607 - November 2016 - 10.0.14393.0: `0180020016800100`

acpi.sys - Windows 10 1607 - November 2016 - 10.0.14393.0: `018062002280`

http.sys - Windows 10 1607 - November 2016 - 10.0.14393.351: `01803200df80`
