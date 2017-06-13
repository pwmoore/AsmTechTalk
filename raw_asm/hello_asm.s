global _start
section .text

_start:
    mov     eax, 4
    mov     ebx, 1
    mov     edx, _len
    mov     ecx, _msg
    int     0x80 
    
    mov     eax, 1
    xor     ebx, ebx
    int     0x80

_msg db "Hello, Assembly!", 10
_len equ $ - _msg 
