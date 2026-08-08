# HPKE Examples

Demonstrates HPKE (Hybrid Public Key Encryption, RFC 9180): public-key
encryption built from a key encapsulation mechanism (KEM), a key derivation
function (KDF), and an authenticated cipher (AEAD).

To build wolfSSL for these examples run `./configure --enable-hpke --enable-aesgcm --enable-curve25519 --enable-ecc && make && sudo make install`

* `hpke_test.c` - one-shot seal/open (`wc_HpkeSealBase()` / `wc_HpkeOpenBase()`)
  with all supported KEM/KDF/AEAD combinations.
* `hpke_context.c` - seal/open contexts (`wc_HpkeInitSealContext()` /
  `wc_HpkeContextSealBase()` and the open equivalents): one key encapsulation
  protecting an ordered sequence of messages.

```sh
make
./hpke_test
HPKE test success
./hpke_context
...
HPKE context test success
```
