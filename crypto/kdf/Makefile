CC=gcc
WOLFSSL_INSTALL_DIR=/usr/local
CFLAGS=-Wall -I$(WOLFSSL_INSTALL_DIR)/include
LIBS=-L$(WOLFSSL_INSTALL_DIR)/lib -lwolfssl -lm

all: hkdf pbkdf2 scrypt-kdf

hkdf: hkdf.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

pbkdf2: pbkdf2.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

scrypt-kdf: scrypt-kdf.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean all check

clean:
	rm -f *.o hkdf pbkdf2 scrypt-kdf

check: all
	out=$$(./hkdf) && printf '%s' "$$out" | grep -q 'matches RFC 5869 Test Case 1'
	out=$$(./pbkdf2) && printf '%s' "$$out" | grep -q 'matches RFC 7914 test vector'
	out=$$(./scrypt-kdf) && printf '%s' "$$out" | grep -q 'matches RFC 7914 test vector'
	@echo "PASS: crypto-kdf checks"
