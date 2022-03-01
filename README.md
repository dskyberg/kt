KT leverages the [formats](https://github.com/rustcrypto/formats) crates from RustCrypto to manage public/private keys in
various formats.  

Different Rust crypto modules accept keys in different formats.  For instance keys generated in the openssl format are not consumable by Ring
without reformatting.  And openssl does not accept all PKCS8 Algorithms (such as id-RSASSA-PSS).  THis utility provides methods way to
convert between compatible document formats, and file encodings.  To a very limited extent, you can also convert algorithms.

## Document conversion:

* PKCS1 <-> PKCS8
* SPKI <-> PKCS8
* SECG <-> PKCS8

## Encoding conversion:

* PEM <-> DER
* JWK <-> PEM (coming soon)
* JWK <-> DER (coming soon)

## Algorithm conversin:

* id-rsaEncryption <-> id-rsassaPss

## Key conversion (coming soon):

* Private key -> Public key (for supported algs)
* Keypair -> Private key
* Keypair -> Public key

## Password Encryption conversion

Add or remove password protection from encrypted keys by simply
specifying passwords args.  KT accepts openssl style password args.

To open a password protected file:

````sh
:> kt show -i protected_file.der --inpass 'pass:my password'
````

To encrypt with a password:
````sh
:> kt show -i unprotected_file.der --outpass 'pass:my password' -e pem
````

To see the full list, run:

````sh
:> kt convert --help
````

# NOT PRODUCTION QUALITY

**Use at your own risk!**

This is a hobby app to refresh my knowledge of cryptographic key formats and to
sharpen my Rust programming skills.  I do attempt to do the right things with key
data - such as using [zeroize] on key bytes.  But the security of this app has not
been verified.

# Examples

## Show key metadata

````sh
:> kt show -i test_data/rsa-2048-private-pk8.der
````

## Convert a key

````sh
:> kt convert -i test_data/rsa-2048-private-pk8.der -f pkcs1 -e pem
````
## Display help for convert

````sh
:> kt convert --help
````
