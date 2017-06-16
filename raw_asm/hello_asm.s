global _start
section .text

; Our entry point is _start rather than main. We will not be
; linking with libc, which normally contains the _start symbol.
; So we provide it ourself as the entry point
_start:
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
