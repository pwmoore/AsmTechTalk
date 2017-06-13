hello_asm: hello_asm.o hello.o
	$(CC) -m32 -o $@ $^

hello.o: hello.c
	$(CC) -m32 -c $^ -o $@

hello_asm.o: hello_asm.s
	nasm -f elf32 -g hello_asm.s

.PHONY: clean
clean:
	-rm *.o hello_asm
