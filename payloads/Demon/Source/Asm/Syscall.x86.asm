[bits 32]

; export the functions
global _SysSetConfig
global _SysInvoke

section .text
    _SysSetConfig:
        mov ebx, [esp + 0x4]
    ret

    ;; Invoke Syscall and pass given arguments
    _SysInvoke:
        mov edx, esp
        sub edx, 0x4
        mov eax, [ebx + 0x4]    ; set the syscall service number into eax
        jmp DWORD [ebx]         ; jump to the following syscall
    ret                         ; finished execution