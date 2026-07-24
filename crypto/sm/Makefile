CC=gcc
WOLFSSL_INSTALL_DIR=/usr/local
CFLAGS=-Wall -I$(WOLFSSL_INSTALL_DIR)/include
LIBS=-L$(WOLFSSL_INSTALL_DIR)/lib -lwolfssl -lm

all: sm3-hash sm4-gcm-encrypt sm2-sign-verify sm2-ecdh

sm3-hash: sm3-hash.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

sm4-gcm-encrypt: sm4-gcm-encrypt.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

sm2-sign-verify: sm2-sign-verify.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

sm2-ecdh: sm2-ecdh.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean all check

clean:
	rm -f *.o sm3-hash sm4-gcm-encrypt sm2-sign-verify sm2-ecdh

check: all
	out=$$(./sm3-hash) && printf '%s' "$$out" | grep -q 'matches GB/T 32905 test vector'
	out=$$(./sm4-gcm-encrypt) && printf '%s' "$$out" | grep -q 'Tampered tag rejected as expected'
	out=$$(./sm2-sign-verify) && printf '%s' "$$out" | grep -q 'Signature verified'
	out=$$(./sm2-ecdh) && printf '%s' "$$out" | grep -q 'Shared secrets match'
	@echo "PASS: crypto-sm checks"
