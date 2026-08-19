# Examples for PKCS #11 with wolfSSL

These examples demonstrate using wolfSSL's PKCS #11 feature for the following algorithms:

* ECC Key Gen, Sign/Verify and ECDHE (Shared Secret)
* RSA Key Gen and Sign/Verify
* AES GCM

This also includes a TLS server example using a PKCS 11 based key.

## API Reference

See [PKCS11.md](./PKCS11.md) in this folder.

## Setting up and testing SoftHSM version 2

1. Change to source code directory of SoftHSM version 2

    This tool can be found here: https://github.com/opendnssec/SoftHSMv2

    ```
    ./autogen.sh
    ./configure --disable-gost
    sudo make install
    ```

    *Note: May need to install pkg-config and libssl-dev*

2. Change to wolfssl directory

    ```
    ./autogen.sh
    ./configure --enable-pkcs11
    make
    sudo make install
    ```

3. Change to wolfssl-examples/pkcs11 directory

    ```
    ./mksofthsm2_conf.sh
    export SOFTHSM2_CONF=$PWD/softhsm2.conf
    ```

4. Running tests

    `softhsm2-util --init-token --slot 0 --label SoftToken`

    * Use PIN: cryptoki
    * Use User PIN: cryptoki

    Use the slot id from the output:

    `export SOFTHSM2_SLOTID=<slotid>`

    Run the examples:

    `./softhsm2.sh`


## Setting up and testing openCryptoki


1. Change to source code directory of openCryptoki

    This tool can be found here: https://github.com/opencryptoki/opencryptoki

    ```
    ./bootstrap.sh
    ./configure
    make
    ```

    *Note: May need to install flex, bison and openldap-devel [or libldap2-dev]*

2. Setup pkcs11 group and put current user into it

    ```
    sudo groupadd pkcs11
    sudo usermod -a -G pkcs11 $USER
    ```

3. Install library

    ```
    sudo make install
    sudo ldconfig /usr/local/lib
    ```

4. Start the daemon

    `sudo /usr/local/sbin/pkcsslotd`

    *Note: May need to logout and login to be able to use pkcsconf.*

5. Setup token

    ```
    echo "87654321
    SoftToken" | pkcsconf -I -c 3
    ```

    ```
    echo "87654321
    cryptoki
    cryptoki" | pkcsconf -P -c 3
    ```

    ```
    echo "cryptoki
    cryptoki
    cryptoki" | pkcsconf -u -c 3
    ```

6. Start daemon if not running already:

    `sudo /usr/local/sbin/pkcsslotd`

7. Build and install wolfSSL

    Change to wolfssl directory and run:

    ```
    ./autogen.sh
    ./configure --enable-pkcs11
    make
    sudo make install
    ```


8. Running tests

    Change to wolfssl-examples/pkcs11 directory:

    `./opencryptoki.sh`

## Setting up and testing wolfPKCS11

1. Change to source code directory of wolfPKCS11

    This tool can be found here: https://github.com/wolfSSL/wolfPKCS11

    ```
    ./autogen.sh
    ./configure
    make && sudo make install
    ./examples/init_token
    export WOLFPKCS11_DIR=$(pwd)
    ```

2. Change to wolfssl directory

    ```
    ./autogen.sh
    ./configure --enable-aescfb --enable-cryptocb --enable-rsapss --enable-keygen --enable-pwdbased --enable-scrypt --enable-pkcs11 --enable-debug 'C_EXTRA_FLAGS=-DWOLFSSL_PUBLIC_MP -DWC_RSA_DIRECT -DWOLFSSL_PKCS11_RW_TOKENS'
    make
    sudo make install
    ```
    It should be noted WOLFSSL_PKCS11_RW_TOKENS is only needed for adding the keys and certs to the store. Once already in the store this is no longer needed.


## Setting up and testing OP-TEE

[OP-TEE](https://optee.readthedocs.io/) provides a PKCS #11 trusted
application, so private keys can be generated and used inside the TrustZone
secure world and never appear in normal-world memory. This has been tested on
an NXP i.MX95 running OP-TEE 4.4, but nothing here is board specific.

1. Build OP-TEE with the PKCS #11 trusted application

    The TA is not in every OP-TEE build. Enable it with `CFG_PKCS11_TA=y` and
    install the resulting `fd02c9da-306c-48c7-a49c-bbd827ae86ee.ta` where
    `tee-supplicant` looks for TAs. You also need the `optee_client` userspace:
    `tee-supplicant`, `libteec.so.2` and `libckteec.so.0`.

2. Make sure `tee-supplicant` is running

    Every PKCS #11 call fails at `C_Initialize` without it, because the TA
    cannot be loaded. If the libraries are not in the default library path,
    point the loader at them:

    ```
    export LD_LIBRARY_PATH=/path/to/optee/lib
    tee-supplicant -l /path/to/ta/dir &
    ```

3. Change to wolfssl directory

    ```
    ./autogen.sh
    ./configure --enable-pkcs11 --enable-cryptocb-rsa-pad
    make
    sudo make install
    ```

    `--enable-cryptocb-rsa-pad` matters. Without it wolfSSL asks the token for
    raw RSA (`CKM_RSA_X_509`), which OP-TEE's TA does not implement, and RSA
    private key operations fail with `RSA_BUFFER_E` (-131). With it wolfSSL
    uses `CKM_RSA_PKCS` and the RSA examples pass. The same applies to any
    token that declines raw RSA.

4. Change to wolfssl-examples/pkcs11 directory and build

    ```
    make
    ```

5. Initialize the token and run the examples

    OP-TEE tokens come up uninitialized and OP-TEE ships no equivalent of
    `softhsm2-util`, so `pkcs11_inittoken` does it through the PKCS #11 API:

    ```
    ./optee-init.sh
    ```

    That initializes slot 0 and then runs the examples. To use a different
    slot, label or PIN:

    ```
    OPTEE_TOKEN=myToken OPTEE_PIN=1234 ./optee-init.sh 1
    ```

    Once the token is initialized, run the examples on their own with:

    ```
    ./optee.sh
    ```

    Or a single example directly, with the usual argument order:

    ```
    ./pkcs11_genecc libckteec.so.0 0 wolfSSL cryptoki
    ```

### EC keys that both derive and sign

`pkcs11_test` generates a single EC key and then uses it for both ECDH and
ECDSA. PKCS #11 leaves the defaults for `CKA_DERIVE` and `CKA_SIGN` up to the
token: SoftHSM grants both regardless of the template, while OP-TEE grants only
what was asked for.

The examples therefore request both explicitly:

```c
wc_ecc_make_key_ex2(&rng, 32, key, ECC_CURVE_DEF, EC_KEYGEN_FLAGS);
```

`EC_KEYGEN_FLAGS` is `WC_ECC_FLAG_DEC_SIGN | WC_ECC_FLAG_DERIVE` when the
installed wolfSSL has `WC_ECC_FLAG_DERIVE`, and `WC_ECC_FLAG_DEC_SIGN` alone
when it does not. No edit is needed either way: the Makefile probes for the
flag by compiling against the installed headers and defines
`HAVE_WC_ECC_FLAG_DERIVE` when it is present.

The probe exists because neither of the usual tests works here.
`WC_ECC_FLAG_DERIVE` is an enum member rather than a macro, so `#ifdef` cannot
see it, and a version test cannot distinguish the two cases either, because
wolfSSL master and v5.9.2-stable both report `LIBWOLFSSL_VERSION_HEX`
`0x05009002`.

Against a wolfSSL without the flag the key is generated sign-only, which is all
that library can request. `pkcs11_test` then fails on a strict token - the
OP-TEE TA among them - at the first ECDH operation with
`CKR_KEY_FUNCTION_NOT_PERMITTED`, surfacing as `WC_HW_E` (-248). Tokens that
enable `CKA_DERIVE` by default are unaffected.

All the examples pass, including RSA key generation, ECDSA, ECDH, AES-CBC,
AES-GCM, HMAC and RNG.

## TLS Server Example with SoftHSM (RSA)

The example `server-tls-pkcs11` is a server that uses a private key that has been stored on the PKCS #11 device.

The id of the private key is two hex bytes: `0x00, 0x01`

Change this to be the id that you set when importing the key.

1. SoftHSM version 2

    Import private key:

    `softhsm2-util --import ../certs/server-keyPkcs8.pem --slot $SOFTHSM2_SLOTID --id 0001 --label rsa2048`

    Enter PIN: cryptoki

2. Run server and client

    `./server-tls-pkcs11 -lib /usr/local/lib/softhsm/libsofthsm2.so -slot $SOFTHSM2_SLOTID -tokenName SoftToken -userPin cryptoki`

    From wolfssl root:
    `./examples/client/client`

## TLS Server Example with SoftHSM (ECC)

The example `server-tls-pkcs11-ecc` is a server that uses a private key that has been stored on the PKCS #11 device.

The id of the private key is two hex bytes: `0x00, 0x02`

Change this to be the id that you set when importing the key.

1. SoftHSM version 2

    Import private key:

    `softhsm2-util --import ../certs/ecc-keyPkcs8.pem --slot $SOFTHSM2_SLOTID --id 0002 --label ecp256`

    Enter PIN: cryptoki

2. Run server and client

    `./server-tls-pkcs11-ecc -lib /usr/local/lib/softhsm/libsofthsm2.so -slot $SOFTHSM2_SLOTID -tokenName SoftToken -userPin cryptoki`

    From wolfssl root:
    `./examples/client/client -A ./certs/ca-ecc-cert.pem`

## TLS Server Example with wolfPKCS11 (RSA)

The example `server-tls-pkcs11` is a server that uses a private key and optionally a certificate that has been stored on the PKCS #11 device.

1. Import Private Key and Certificate
    ```
    cd $WOLFPKCS11_DIR
    ./examples/add_rsa_key_file -privId "server-rsa2048" -rsa ../certs/server-key.der
    ./examples/add_cert_file -privId "server-rsa2048-id" -label "server-rsa2048-label" -cert ../certs/server-cert.der
    ```

2. Run server and client

    `WOLFPKCS11_TOKEN_PATH=$WOLFPKCS11_DIR ./server-tls-pkcs11 -lib $WOLFPKCS11_DIR/src/.libs/libwolfpkcs11.so -tokenName wolfpkcs11 -userPin wolfpkcs11-test -privKeyId server-rsa2048 -certId server-rsa2048-id`

    From wolfssl root:

    `./examples/client/client`


## Support

For questions please contact wolfSSL support by email at [support@wolfssl.com](mailto:support@wolfssl.com)
