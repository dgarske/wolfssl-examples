# wolfSSL SLH-DSA Example

Demonstrates SLH-DSA (Stateless Hash-Based Digital Signature Algorithm,
FIPS 205, formerly SPHINCS+) key generation, signing and verification with
wolfCrypt.

SLH-DSA's security rests only on hash function assumptions. Compared to
ML-DSA it has
much smaller keys but much larger signatures and slower signing.

## Building wolfSSL

```
./configure --enable-slhdsa
make
sudo make install
```

`--enable-slhdsa` enables the six SHAKE parameter sets. Use
`--enable-slhdsa=yes,sha2` to also enable the SHA2 parameter sets.

## Building and running the example

```
make
./slh_dsa_test [-v] [-s <parameter set>] [-m <message>]
```

Parameter sets: `shake-128s`, `shake-128f`, `shake-192s`, `shake-192f`,
`shake-256s`, `shake-256f` (and `sha2-*` equivalents when enabled). The `s`
(small) variants trade signing speed for smaller signatures; the `f` (fast)
variants sign faster but produce larger signatures. Default is `shake-128f`.

Example:

```
$ ./slh_dsa_test -s shake-128f
info: using SLH-DSA-shake-128f: pub 32 bytes, priv 64 bytes, sig 17088 bytes
info: making key
info: signing message
info: verify message good
info: corrupted signature rejected as expected
info: done
```
