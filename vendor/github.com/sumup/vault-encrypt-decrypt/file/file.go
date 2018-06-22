package file

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

func ReadPublicKeyFromPath(publicKeyPath string) (*rsa.PublicKey, error) {
	publicKeyContent, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read contents of public_key at public_key_path: %s. Err: %s", publicKeyPath, err)
	}

	block, _ := pem.Decode(publicKeyContent)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse PKCS1 public key. Err: %s", err)
	}

	switch pub := key.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		return nil, errors.New("public key is not a rsa public key")
	}
}

func ReadPrivateKeyFromPath(privateKeyPath string) (*rsa.PrivateKey, error) {
	privateKeyContent, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read contents of private_key at private_key_path: %s. Err: %s", privateKeyPath, err)
	}

	block, _ := pem.Decode(privateKeyContent)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse PKCS1 private key. Err: %s", err)
	}

	return key, nil
}
