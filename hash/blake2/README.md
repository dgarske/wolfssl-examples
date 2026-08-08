# wolfSSL BLAKE2 Examples

Demonstrates the dedicated BLAKE2b/BLAKE2s wolfCrypt APIs (`wc_Blake2b*` /
`wc_Blake2s*`), including BLAKE2's native keyed mode.

* `blake2b-hash.c` - incremental BLAKE2b-512 hashing, verified against the
  RFC 7693 Appendix A test vector.
* `blake2s-hash.c` - incremental BLAKE2s-256 hashing, verified against the
  RFC 7693 Appendix B test vector.
* `blake2-keyed-mac.c` - keyed BLAKE2b as a MAC via
  `wc_InitBlake2b_WithKey()`. Unlike SHA-2, BLAKE2 does not need the HMAC
  construction to be used as a MAC.

## Building wolfSSL

```
./configure --enable-blake2 --enable-blake2s
make
sudo make install
```

`--enable-blake2` enables BLAKE2b, `--enable-blake2s` enables BLAKE2s.

## Building and running the examples

```
make
./blake2b-hash [message]
./blake2s-hash [message]
./blake2-keyed-mac
```

With no argument the hash examples digest `"abc"` and compare against the
RFC 7693 known-answer vectors.
