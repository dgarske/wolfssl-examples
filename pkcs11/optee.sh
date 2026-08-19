#!/bin/sh

# Run the PKCS#11 examples against OP-TEE's PKCS#11 trusted application.
#
# The token must already be initialized - use ./optee-init.sh for that.
#
# Requires tee-supplicant to be running; without it every call fails at
# C_Initialize because the TA cannot be loaded.

# Only treat the first argument as a slot id if it is numeric, so that
# "./optee.sh pkcs11_rsa" runs one example against the default slot instead of
# silently consuming the example name as a slot id.
case "${1:-}" in
  '' | *[!0-9]* ) ;;
  * ) OPTEE_SLOTID=$1; shift ;;
esac

# OP-TEE's PKCS#11 client library. It is usually installed as a normal shared
# library, but on an embedded rootfs it is often staged elsewhere, in which
# case set OPTEE_LIB (and LD_LIBRARY_PATH) to point at it.
if [ -z "$OPTEE_LIB" ]
then
  OPTEE_LIB=libckteec.so.0
fi

if [ -z "$OPTEE_SLOTID" ]
then
  OPTEE_SLOTID=0
fi
if [ -z "$OPTEE_TOKEN" ]
then
  OPTEE_TOKEN=wolfSSL
fi
if [ -z "$OPTEE_PIN" ]
then
  OPTEE_PIN=cryptoki
fi

rc=0

run_example()
{
  name=$1
  shift
  echo
  echo "# $name"
  if ! "$@" "$OPTEE_LIB" "$OPTEE_SLOTID" "$OPTEE_TOKEN" "$OPTEE_PIN"
  then
    echo "# FAILED: $name"
    rc=1
  fi
}

echo "# Using slot ID: $OPTEE_SLOTID"
echo "# Using library: $OPTEE_LIB"
echo "# Using token:   $OPTEE_TOKEN"

if [ $# -gt 0 ]
then
  for example in "$@"
  do
    run_example "$example" "./$example"
  done
else
  run_example "RSA example" ./pkcs11_rsa
  run_example "ECC example" ./pkcs11_ecc
  run_example "Generate ECC example" ./pkcs11_genecc
  run_example "AES-GCM example" ./pkcs11_aesgcm
  run_example "AES-CBC example" ./pkcs11_aescbc
  run_example "HMAC example" ./pkcs11_hmac
  run_example "Random Number Generation example" ./pkcs11_rand
  run_example "PKCS#11 test" ./pkcs11_test
fi

echo
if [ $rc -eq 0 ]
then
  echo "# All PKCS#11 examples passed"
else
  echo "# One or more PKCS#11 examples FAILED"
fi

exit $rc
