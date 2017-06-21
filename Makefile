all: deps
	$(MAKE) -C raw_asm
	$(MAKE) -C asm_loop
	$(MAKE) -C c_asm
	$(MAKE) -C sc_emu
	$(MAKE) -C jithappens

.PHONY: clean deps
clean: 
	-$(MAKE) clean -C raw_asm
	-$(MAKE) clean -C asm_loop
	-$(MAKE) clean -C c_asm 
	-$(MAKE) clean -C sc_emu
	-$(MAKE) clean -C jithappens

deps:
	./makedeps.sh
