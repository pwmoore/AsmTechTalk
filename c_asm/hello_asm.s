global say_hello
section .text

; int say_hello(void)
say_hello:
    mov     eax, 4                  ; set eax = SYS_write
    mov     ebx, 1                  ; set ebx = stdout
    mov     edx, _len               ; edx = len
    mov     ecx, _msg               ; ecx = pointer to msg
    int     0x80                    ; write(1, _msg, _len)
    
    mov     eax, 1                  ; set eax = SYS_exit
    xor     ebx, ebx                ; set exit() value to 0
    int     0x80                    ; exit(0)

_msg db "Hello, Assembly!", 10      ; Note the newline at the end
_len equ $ - _msg                   ; Length of msg
