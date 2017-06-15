LIB=-lunicorn -lcapstone -lpthread 

shellcode_emulator: shellcode_emulator.c
	cc -o $@ $^ $(LIB)

.PHONY: clean
clean:
	rm shellcode_emulator
