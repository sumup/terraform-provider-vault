package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

func pkcs7Pad(bytesValue []byte, blockSize int) ([]byte, error) {
	if bytesValue == nil || len(bytesValue) == 0 {
		return nil, fmt.Errorf("empty value to pad. Given value: %s", bytesValue)
	}

	if blockSize <= 0 {
		return nil, errors.New("blocksize is invalid. it must be greater than or equal to 1")
	}
	padSize := blockSize - (len(bytesValue) % blockSize)
	if padSize == 0 {
		padSize = blockSize
	}
	pad := bytes.Repeat([]byte{byte(padSize)}, padSize)
	return append(bytesValue, pad...), nil
}

func pkcs7Unpad(bytesValue []byte, blockSize int) ([]byte, error) {
	if bytesValue == nil || len(bytesValue) == 0 {
		return nil, fmt.Errorf("empty value to unpad. Given value: %s", bytesValue)
	}

	if blockSize <= 0 {
		return nil, errors.New("blocksize is invalid. it must be greater than or equal to 1")
	}

	if len(bytesValue)%blockSize != 0 {
		return nil, fmt.Errorf("value length is invalid. value is probably not properly padded via pkcs7. value length: %d", len(bytesValue))
	}

	padSize := int(bytesValue[len(bytesValue)-1])

	pad := bytesValue[len(bytesValue)-padSize:]
	for _, padByte := range pad {
		if padByte != byte(padSize) {
			return nil, errors.New("invalid padding")
		}
	}

	return bytesValue[:len(bytesValue)-padSize], nil
}

func GeneratePassphrase(length int) ([]byte, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func EncryptPassphrase(publicKey *rsa.PublicKey, passphrase []byte) (string, error) {
	encryptedPassphrase, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, passphrase)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(encryptedPassphrase), nil
}

func Encrypt(passphrase []byte, value string) (string, error) {
	valueBytes := []byte(value)

	paddedValueBytes, err := pkcs7Pad(valueBytes, aes.BlockSize)
	if err != nil {
		return "", err
	}

	if len(paddedValueBytes)%aes.BlockSize != 0 {
		return "", errors.New("value is not a multiple of the block size")
	}

	block, err := aes.NewCipher(passphrase)
	if err != nil {
		return "", fmt.Errorf("unable to create aes cipher. Err: %s", err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(paddedValueBytes))

	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], paddedValueBytes)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func DecryptBase64Passphrase(privateKey *rsa.PrivateKey, base64Value string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(base64Value)
	if err != nil {
		return nil, fmt.Errorf("unable to decode base64 value: %s. Err: %s", base64Value, err)
	}

	return rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
}

func Decrypt(passphrase, base64Value string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(base64Value)
	if err != nil {
		return "", fmt.Errorf("unable to decode base64 value: %s. Err: %s", base64Value, err)
	}

	block, err := aes.NewCipher([]byte(passphrase))
	if err != nil {
		return "", fmt.Errorf("unable to create aes cipher. Err: %s", err)
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("encrypted value is too short. Value: %s", ciphertext)
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		return "", fmt.Errorf("encrypted value is not a multiple of the block size. Value: %s", ciphertext)
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(ciphertext, ciphertext)

	plaintext, err := pkcs7Unpad(ciphertext, aes.BlockSize)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
