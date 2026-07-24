# wolfSSL MIKEY-SAKKE Example

Demonstrates the identity-based crypto behind MIKEY-SAKKE (Multimedia
Internet KEYing with Sakai-Kasahara Key Encryption, RFC 6509), the key
exchange used by secure-voice systems such as 3GPP Mission Critical Push To
Talk:

* ECCSI (Elliptic Curve-based Certificateless Signatures for Identity-based
  encryption, RFC 6507) - identity-based signatures (`wc_*Eccsi*`)
* SAKKE (Sakai-Kasahara Key Encryption, RFC 6508) - identity-based key
  encapsulation (`wc_*Sakke*`)

In identity-based crypto there are no per-user certificates: a user's public
key is their identity string (phone number, email). A Key Management Service
(KMS) holds master secrets and provisions each user's private material out of
band.

The example runs the whole flow in one program:

1. KMS creates master ECCSI and SAKKE keys.
2. KMS provisions Alice's ECCSI signing pair - Secret Signing Key (SSK) and
   Public Validation Token (PVT) - for her identity, and Bob's SAKKE
   Receiver Secret Key (RSK) for his.
3. Alice generates a 128-bit Shared Secret Value, encapsulates it to Bob's
   identity, and ECCSI-signs the payload.
4. Bob verifies the signature against Alice's identity, derives the SSV with
   his RSK, and both sides end up with the same session key.

## Building wolfSSL

```
./configure --enable-eccsi --enable-sakke
make
sudo make install
```

## Building and running the example

```
make
./mikey-sakke
```

Expected output ends with `Shared Secret Values match`.
