CC=gcc
WOLFSSL_INSTALL_DIR=/usr/local
CFLAGS=-Wall -I$(WOLFSSL_INSTALL_DIR)/include -g
#LIBS= -lwolfssl -lm
LIBS= -L$(WOLFSSL_INSTALL_DIR)/lib -lwolfssl -lm

all: srp srp_gen srp_sha256

srp.o: srp.c srp_params.h srp_store.h
	$(CC) -c -o $@ srp.c $(CFLAGS)

srp_gen.o: srp_gen.c srp_params.h
	$(CC) -c -o $@ srp_gen.c $(CFLAGS)

srp_sha256.o: srp_sha256.c srp_params_2048.h
	$(CC) -c -o $@ srp_sha256.c $(CFLAGS)

srp: srp.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

srp_gen: srp_gen.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

srp_sha256: srp_sha256.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean check

clean:
	rm -f *.der *.x963 *.o srp srp_gen srp_sha256

check: srp srp_gen srp_sha256
	out=$$(./srp wolfssl password) && printf '%s' "$$out" | grep -q 'Client verified server proof'
	out=$$(./srp_gen wolfssl password) && printf '%s' "$$out" | grep -qF 'static const byte verifier['
	out=$$(./srp_sha256) && printf '%s' "$$out" | grep -q 'Session keys match'
	@echo "PASS: pk-srp checks"
