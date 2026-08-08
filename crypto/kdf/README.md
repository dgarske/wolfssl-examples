# wolfSSL KDF Examples

Demonstrates the main wolfCrypt key derivation functions, each verified
against its RFC known-answer test vector.

* `hkdf.c` - HKDF (RFC 5869): extract-then-expand derivation from existing
  keying material, shown both as separate `wc_HKDF_Extract()` /
  `wc_HKDF_Expand()` steps and as the one-shot `wc_HKDF()`.
* `pbkdf2.c` - PBKDF2 (RFC 2898) via `wc_PBKDF2()`: deriving keys from
  passwords with a salt and an iteration work factor.
* `scrypt-kdf.c` - scrypt (RFC 7914) via `wc_scrypt()`: memory-hard
  password-based derivation for stronger resistance to GPU/ASIC attacks.

Use HKDF when the input is already a high-entropy secret (e.g. a DH shared
secret); use PBKDF2 or scrypt when the input is a password.

## Building wolfSSL

```
./configure --enable-hkdf --enable-scrypt
make
sudo make install
```

PBKDF2 is enabled by default (disabled only by `NO_PWDBASED`).

## Building and running the examples

```
make
./hkdf
./pbkdf2
./scrypt-kdf
```
