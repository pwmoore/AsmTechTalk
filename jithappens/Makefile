LIB=-lcapstone -lkeystone -lreadline
CFLAGS=-L/usr/local/lib -v

jithappens: jithappens.c
	$(CC) $(CFLAGS) -o $@ $^ $(LIB)

.PHONY: clean
clean:
	rm jithappens

