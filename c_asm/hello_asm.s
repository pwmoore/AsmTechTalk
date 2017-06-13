global _say_hello
section .text

_say_hello:
    mov     eax, 4
    mov     ebx, 1
    mov     edx, _len
    mov     ecx, _msg
    int     0x80 
    
    xor     eax, eax
    ret

_msg db "Hello, Assembly!", 10
_len equ $ - _msg 
