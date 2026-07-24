CC=gcc
WOLFSSL_INSTALL_DIR=/usr/local
CFLAGS= -I$(WOLFSSL_INSTALL_DIR)/include -Wall
LIBS= -L$(WOLFSSL_INSTALL_DIR)/lib -lwolfssl

all: hpke_test hpke_context

hpke_test: hpke_test.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

hpke_context: hpke_context.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean check all

clean:
	rm -f *.o hpke_test hpke_context

check: all
	out=$$(./hpke_test) && printf '%s' "$$out" | grep -q 'HPKE test success'
	out=$$(./hpke_context) && printf '%s' "$$out" | grep -q 'HPKE context test success'
	@echo "PASS: pk-hpke checks"
