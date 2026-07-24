# wolfSSL SipHash Example

Demonstrates SipHash-2-4 keyed MACs with the `wc_SipHash*` API: one-shot
64-bit and 128-bit tags plus the incremental Init/Update/Final interface,
checked against the reference implementation's test vector.

SipHash is a fast keyed pseudorandom function for short inputs. Typical uses
are hash-table flooding protection and lightweight per-packet authentication;
it is not a general-purpose collision-resistant hash.

## Building wolfSSL

```
./configure --enable-siphash
make
sudo make install
```

## Building and running the example

```
make
./siphash-mac
```
