CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2
LDFLAGS ?=
STATIC_LDFLAGS ?= -static
TEST_LDFLAGS ?= $(STATIC_LDFLAGS)

all: sigmund

sigmund: src/sigmund.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(STATIC_LDFLAGS) -o $@ $<

sigmund-dynamic: src/sigmund.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o sigmund $<

clean:
	rm -f sigmund

.PHONY: all clean test

test:
	$(CC) $(CFLAGS) $(LDFLAGS) $(TEST_LDFLAGS) -DSIGMUND_BOOT_ID_PATH='"/tmp/sigmund_test_boot_id"' -o sigmund src/sigmund.c
	@bash tests/test_sigmund.sh
