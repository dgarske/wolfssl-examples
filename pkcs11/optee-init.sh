#!/bin/sh

# Initialize an OP-TEE PKCS#11 token and then run the examples against it.
#
# OP-TEE tokens come up uninitialized and OP-TEE ships no equivalent of
# softhsm2-util, so pkcs11_inittoken does it through the PKCS#11 API. Re-running
# this is safe: an already-initialized token is left alone.

set -e

cd "$(dirname "$0")"

# Same argument convention as optee.sh: an optional slot id first, then any
# specific examples to run.
# Only treat the first argument as a slot id if it is numeric, so that
# "./optee-init.sh pkcs11_rsa" runs one example against the default slot instead of
# silently consuming the example name as a slot id.
case "${1:-}" in
  '' | *[!0-9]* ) ;;
  * ) OPTEE_SLOTID=$1; shift ;;
esac

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
if [ -z "$OPTEE_SOPIN" ]
then
  OPTEE_SOPIN=cryptoki
fi
if [ -z "$OPTEE_PIN" ]
then
  OPTEE_PIN=cryptoki
fi

./pkcs11_inittoken "$OPTEE_LIB" "$OPTEE_SLOTID" "$OPTEE_TOKEN" \
    "$OPTEE_SOPIN" "$OPTEE_PIN"

OPTEE_LIB="$OPTEE_LIB" OPTEE_TOKEN="$OPTEE_TOKEN" OPTEE_PIN="$OPTEE_PIN" \
    exec ./optee.sh "$OPTEE_SLOTID" "$@"
