CC=gcc
WOLFSSL_INSTALL_DIR=/usr/local
CFLAGS=-Wall -I$(WOLFSSL_INSTALL_DIR)/include
LIBS=-L$(WOLFSSL_INSTALL_DIR)/lib -lwolfssl -lm

all: blake2b-hash blake2s-hash blake2-keyed-mac

blake2b-hash: blake2b-hash.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

blake2s-hash: blake2s-hash.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

blake2-keyed-mac: blake2-keyed-mac.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean all check

clean:
	rm -f *.o blake2b-hash blake2s-hash blake2-keyed-mac

check: all
	out=$$(./blake2b-hash) && printf '%s' "$$out" | grep -q 'matches RFC 7693 test vector'
	out=$$(./blake2s-hash) && printf '%s' "$$out" | grep -q 'matches RFC 7693 test vector'
	out=$$(./blake2-keyed-mac) && printf '%s' "$$out" | grep -q 'Wrong key rejected'
	@echo "PASS: hash-blake2 checks"
