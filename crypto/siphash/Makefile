CC=gcc
WOLFSSL_INSTALL_DIR=/usr/local
CFLAGS=-Wall -I$(WOLFSSL_INSTALL_DIR)/include
LIBS=-L$(WOLFSSL_INSTALL_DIR)/lib -lwolfssl -lm

.PHONY: all clean check

all: siphash-mac

siphash-mac: siphash-mac.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm -f *.o siphash-mac

check: siphash-mac
	out=$$(./siphash-mac) && printf '%s' "$$out" | grep -q 'Incremental MAC matches one-shot MAC'
	@echo "PASS: crypto-siphash checks"
