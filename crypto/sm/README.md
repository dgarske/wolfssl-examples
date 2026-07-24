# wolfSSL SM2/SM3/SM4 Examples

Demonstrates the Chinese national (ShangMi) cryptographic algorithms at the
wolfCrypt level:

* `sm3-hash.c` - SM3 hash (Chinese national standard GB/T 32905-2016),
  checked against the standard's "abc" test vector.
* `sm4-gcm-encrypt.c` - SM4-GCM (GB/T 32907-2016) authenticated encryption
  with tamper detection.
* `sm2-sign-verify.c` - SM2 (GB/T 32918) digital signatures, including the
  identity-based "ZA" digest step via `wc_ecc_sm2_create_digest()`.
* `sm2-ecdh.c` - ECDH shared-secret agreement on the SM2 curve.

## Building wolfSSL

The SM algorithm implementations ship in the separate
[wolfSSL/wolfsm](https://github.com/wolfSSL/wolfsm) overlay, so install that
into a wolfSSL source tree first:

```
git clone https://github.com/wolfSSL/wolfsm
git clone https://github.com/wolfSSL/wolfssl
cd wolfsm
./install.sh ../wolfssl
cd ../wolfssl
./autogen.sh
./configure --enable-sm2 --enable-sm3 --enable-sm4-gcm
make
sudo make install
```

Other SM4 modes are available with `--enable-sm4-ecb`, `--enable-sm4-cbc`,
`--enable-sm4-ctr` and `--enable-sm4-ccm`.

## Building and running the examples

```
make
./sm3-hash [message]
./sm4-gcm-encrypt
./sm2-sign-verify [message]
./sm2-ecdh
```
