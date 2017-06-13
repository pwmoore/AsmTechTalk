hello_asm: hello_asm.o
	ld -m elf_i386 -g hello_asm.o -o hello_asm

hello_asm.o: hello_asm.s
	nasm -f elf32 -g hello_asm.s

.PHONY: clean
clean:
	rm hello_asm hello_asm.o
