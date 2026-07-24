CC = gcc

WOLFSSL_INSTALL_DIR = /usr/local

WOLFSSL_CFLAGS = -Wextra -Werror -Wall -I$(WOLFSSL_INSTALL_DIR)/include
WOLFSSL_LIBS   = -L$(WOLFSSL_INSTALL_DIR)/lib -lm -lwolfssl

DEBUG_FLAGS    = -g -DDEBUG

all: slh_dsa_test

slh_dsa_test: slh_dsa.c
	$(CC) -o $@ $^ $(WOLFSSL_CFLAGS) $(WOLFSSL_LIBS) $(DEBUG_FLAGS)

.PHONY: clean all check

clean:
	rm -f *.o slh_dsa_test

check: slh_dsa_test
	out=$$(./slh_dsa_test -s shake-128f) && printf '%s' "$$out" | grep -q 'info: verify message good'
	out=$$(./slh_dsa_test -s shake-192f -m "wolfssl-examples CI") && printf '%s' "$$out" | grep -q 'info: verify message good'
	@echo "PASS: pq-slh-dsa checks"
