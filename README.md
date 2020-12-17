# ima-keyring-signer
IMA file signer using keyring asymmetric keys

This tool can be used to sign files with IMA signatures with a key that's stored
in the kernel Keyring.

## Steps to try
Generate a new RSA key:

`$ openssl genrsa | openssl pkcs8 -topk8 -nocrypt -outform DER -out privatekey.der`

Create a public certificate with the key:

`$ openssl req -x509 -key privatekey.der -out certificate.pem -days 365 -keyform DER`

Load the key onto the keyring:

`$ keyctl padd asymmetric $description @u <privatekey.der`
(if this fails with `Bad message`, load the PKCS8 key parser: `modprobe pkcs8_key_parser`).

Sign a file:

`$ cargo run -- $description certificate.pem sha256 -- myfile.txt`

In order to embed the signature as extended attribute, run:

`$ cargo run -- $description certificate.pem sha256 -- --xattr myfile.txt`

Encode the certificate for verification:

`$ openssl x509 -in certificate.pem -inform PEM -out certificate.der -outform DER`

Verify the signature:

`$ evmctl ima_verify --sigfile --key certificate.der -v myfile.txt`


## Usage
The general usage:

`ima-keyring-signer <key-description> <public-pem-cert-path> <hash-algo> [file ...]`

The supported hash algorithms are: sha1, sha256

In the `file` section, you can add a `--xattr`. When you add that, any following files will have the signature embedded as extended attribute.
Use `--sigfile` to change back to detached signature files.
