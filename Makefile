CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2

all: sigmund

sigmund: src/sigmund.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f sigmund

.PHONY: all clean test

test:
	$(CC) $(CFLAGS) -DSIGMUND_BOOT_ID_PATH='"/tmp/sigmund_test_boot_id"' -o sigmund src/sigmund.c
	@bash tests/test_sigmund.sh
