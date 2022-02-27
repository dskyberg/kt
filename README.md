KT performs very simply key display and conversion functions with 100% Rust code.
 
KT leverages the [formats](https://github.com/rustcrypto/formats) crates from RustCrypto to manage public/private keys in
various formats.  To see the full list, run:

````
kt convert --help
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
> kt show -i test_data/rsa-2048-private-pk8.der
````

## Convert a key

````sh
> kt convert -i test_data/rsa-2048-private-pk8.der -f pkcs1 -e pem
````
## Display help for convert

````sh
> kt convert --help
````
