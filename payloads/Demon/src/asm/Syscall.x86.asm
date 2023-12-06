[bits 32]

; export the functions
global _SysSetConfig
global _SysInvoke
global _IsWoW64

section .text
    _SysSetConfig:
        mov edx, [esp + 0x4]
    ret

    ;; Invoke Syscall and pass given arguments
    _SysInvoke:
        mov ebx, [edx + 0x0]    ; set the address of the syscall
        mov eax, [edx + 0x4]    ; set the syscall service number into eax
        mov edx, esp
        sub edx, 0x4
        call DWORD ebx          ; call the following syscall
    ret                         ; finished execution

    _IsWoW64:
        mov eax, [fs:0xc0]
        test eax, eax
        jne wow64
        mov eax, 0
        ret
        wow64:
        mov eax, 1
    ret