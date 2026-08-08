CC=gcc
WOLFSSL_INSTALL_DIR=/usr/local
CFLAGS=-Wall -I$(WOLFSSL_INSTALL_DIR)/include
LIBS=-L$(WOLFSSL_INSTALL_DIR)/lib -lwolfssl -lm

.PHONY: all clean check

all: mikey-sakke

mikey-sakke: mikey-sakke.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm -f *.o mikey-sakke

check: mikey-sakke
	out=$$(./mikey-sakke) && printf '%s' "$$out" | grep -q 'Shared Secret Values match'
	@echo "PASS: pk-mikey-sakke checks"
