
[BITS 32]

extern _Entry

global _Start
global _GetRIP
global _KaynCaller

section .text$A
	_Start:
        push    esi
        mov		esi, esp
        and		esp, 0FFFFFFF0h

        sub		esp, 020h
        call    _Entry

        mov		esp, esi
        pop		esi
    ret

section .text$F
    _KaynCaller:
           call caller
       caller:
           pop ecx
       loop:
           xor ebx, ebx
           mov ebx, 0x5A4D
           inc ecx
           cmp bx,  [ ecx ]
           jne loop
           xor eax, eax
           mov ax,  [ ecx + 0x3C ]
           add eax, ecx
           xor ebx, ebx
           add bx,  0x4550
           cmp bx,  [ eax ]
           jne loop
           mov eax, ecx
       ret

    _GetRIP:
        call    retptr

    retptr:
        pop	eax
        sub	eax, 5
    ret
