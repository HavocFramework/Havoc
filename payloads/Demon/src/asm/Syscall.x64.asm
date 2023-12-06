[bits 64]

; export the functions
global SysSetConfig
global SysInvoke

section .text
    SysSetConfig:
        mov r11, rcx
    ret

    ;; Invoke Syscall and pass given arguments
    SysInvoke:
        mov r10, rcx
        mov eax, [r11 + 0x8]    ; set the syscall service number into eax
        jmp QWORD [r11]         ; jump to the following syscall
    ret                         ; finished execution