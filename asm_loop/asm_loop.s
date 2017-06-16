global main
section .text

; Declare printf as an external function
extern printf

; Since we're linking with libc, our entry point is main. The libc runtime
; calls main()
main:
    push    ebp                                 ; Save off ebp
    mov     ebp, esp                            ; Move the stack pointer to the new frame
    sub     esp, 0x10                           ; Make space for locals, aligned to 0x10
    mov     dword [ebp-4], 0                    ; Set counter variable to 0

; Beginning of loop
_loop:
    mov     ecx, dword [ebp-4]                  ; ecx = counter
    push    ecx                                 ; Push counter onto stack
    mov     eax, _fmt_string                    ; Get a pointer to our format string
    push    eax                                 ; Push the pointer to the stack
    call    printf                              ; printf("Iteration %d\n", counter);
    add     esp, 8                              ; Clean up the stack
    mov     ecx, dword [ebp-4]                  ; ecx = counter
    add     ecx, 1                              ; counter += 1
    mov     dword [ebp-4], ecx                  ; Write the new value back to counter
    cmp     ecx, 10                             ; Is ecx <= 10?
    jge     _done                               ; If so, go to _done
    jmp     _loop                               ; Otherwise go back to the top
    
; End of loop
_done:
    xor     eax, eax                            ; Clear our return value
    add     esp, 0x10                           ; Clean up stack
    pop     ebp                                 ; Restore ebp
    ret                                         ; Return

_fmt_string db "Iteration %d", 10, 0
