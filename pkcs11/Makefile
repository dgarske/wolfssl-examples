# PKCS11 Examples Makefile
CC       = gcc
WOLFSSL_INSTALL_DIR = /usr/local
CFLAGS   = -Wall -I$(WOLFSSL_INSTALL_DIR)/include
# -ldl for pkcs11_inittoken, which dlopen()s the PKCS#11 library. Harmless
# on glibc >= 2.34 where libdl is merged into libc, required on older ones.
LIBS     = -L$(WOLFSSL_INSTALL_DIR)/lib -lm -ldl

# option variables
DYN_LIB         = -lwolfssl
STATIC_LIB      = $(WOLFSSL_INSTALL_DIR)/lib/libwolfssl.a
DEBUG_FLAGS     = -g -DDEBUG
DEBUG_INC_PATHS = -MD
OPTIMIZE        = -Os

# WC_ECC_FLAG_DERIVE is an enum member, not a macro, so the preprocessor cannot
# test for it - and a version check cannot either, because wolfSSL master and
# v5.9.2-stable both report LIBWOLFSSL_VERSION_HEX 0x05009002. Probe by
# compiling against the installed headers instead, which is accurate on any
# release, snapshot or git build.
# Skipped for goals that never compile C, so "make clean" does not spawn a
# throwaway compile - which would also fail noisily where wolfSSL is absent.
ifeq ($(filter clean,$(MAKECMDGOALS)),)
HAVE_ECC_FLAG_DERIVE := $(shell printf '%s\n' \
	'#include <wolfssl/options.h>' \
	'#include <wolfssl/wolfcrypt/ecc.h>' \
	'int main(void){return (int)WC_ECC_FLAG_DERIVE;}' \
	| $(CC) -I$(WOLFSSL_INSTALL_DIR)/include -x c - -o /dev/null 2>/dev/null \
	&& echo yes)
endif

# Options
#CFLAGS+=$(DEBUG_FLAGS)
CFLAGS+=$(OPTIMIZE)
ifeq ($(HAVE_ECC_FLAG_DERIVE),yes)
CFLAGS+=-DHAVE_WC_ECC_FLAG_DERIVE
endif
#LIBS+=$(STATIC_LIB) -ldl -lm
LIBS+=$(DYN_LIB)

# build targets
SRC=$(wildcard *.c)
TARGETS=$(patsubst %.c, %, $(SRC))

.PHONY: clean all

all: $(TARGETS)

debug: CFLAGS+=$(DEBUG_FLAGS)
debug: all

# build template
%: %.c
	$(CC) -o $@ $< $(CFLAGS) $(LIBS)

clean:
	rm -f $(TARGETS)
