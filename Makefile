CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2

all: sigmund

sigmund: src/sigmund.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f sigmund

.PHONY: all clean
