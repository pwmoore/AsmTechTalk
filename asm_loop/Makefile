# Link with gcc to bring in libc
asm_loop: asm_loop.o
	gcc -m32 -o $@ $^

# Build our object file
asm_loop.o: asm_loop.s
	nasm -f elf32 -g asm_loop.s

.PHONY: clean
clean:
	rm asm_loop asm_loop.o
