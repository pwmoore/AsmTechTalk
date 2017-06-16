# Link our object file as a 32-bit ELF binary
hello_asm: hello_asm.o
	ld -m elf_i386 -g hello_asm.o -o hello_asm

# Use nasm to build our object file
hello_asm.o: hello_asm.s
	nasm -f elf32 -g hello_asm.s

.PHONY: clean
clean:
	rm hello_asm hello_asm.o
