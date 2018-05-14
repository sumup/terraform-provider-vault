# vault-encrypt-decrypt

Encryption/decryption of values for https://github.com/sumup/terraform_mod_vault

## Prerequisites

1. RSA public and private key pair for asymmetric encryption (using `openssl`, `cfssl` or whichever works for you).
1. Passfile already encrypted using RSA public key and encoded in base64 standard encoding as per [RFC 4648 section 3.2](https://tools.ietf.org/html/rfc4648#section-3.2). For Linux systems, `base64` is sufficient.

## Usage

### Encryption

```shell
vault-encrypt-decrypt encrypt \
--public_key_path ./test-fixtures/secret-key.pem \
--in ./test-fixtures/test.txt \
--out ./test-fixtures/test.encrypted
```

### Decryption

```shell
vault-encrypt-decrypt decrypt \
--private_key_path ./test-fixtures/secret-key.pem \
--in ./test-fixtures/test.encrypted \
--out ./test-fixtures/test.decrypted
```

### INI file to Terraform (temporary feature)

```shell
vault-encrypt-decrypt ini \
--public_key_path ./test-fixtures/secret-pubkey.pem \
--private_key_path ./test-fixtures/secret-key.pem \
--in ./my_secrets.ini \
--out ./my_secrets.tf
```
