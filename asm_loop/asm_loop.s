global main
section .text

extern printf

main:
    push    ebp
    mov     ebp, esp
    sub     esp, 0x10
    mov     dword [ebp-4], 0 
_loop:
    mov     ecx, dword [ebp-4]
    push    ecx
    mov     eax, _fmt_string
    push    eax
    call    printf
    add     esp, 8
    mov     ecx, dword [ebp-4]
    add     ecx, 1
    mov     dword [ebp-4], ecx
    cmp     ecx, 10
    jge     _done
    jmp     _loop
    
_done :
    xor     eax, eax
    add     esp, 0x10
    pop     ebp
    ret

_fmt_string db "Iteration %d", 10, 0
