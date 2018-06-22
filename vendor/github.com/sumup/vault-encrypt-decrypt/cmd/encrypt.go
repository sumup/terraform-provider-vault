package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/sumup/vault-encrypt-decrypt/encryption"
	"io/ioutil"
	"os"
	"github.com/sumup/vault-encrypt-decrypt/file"
	"github.com/sumup/vault-encrypt-decrypt/pkg"
)

var encryptPublicKeyPath string
var encryptInFilePath string
var encryptOutFilePath string

func init() {
	encryptCommand.PersistentFlags().StringVarP(&encryptPublicKeyPath, "public_key_path", "", "", "Path to RSA public key used to encrypt runtime random generated passphrase.")
	encryptCommand.PersistentFlags().StringVarP(&encryptInFilePath, "in", "", "", "Path to the input file.")
	encryptCommand.PersistentFlags().StringVarP(&encryptOutFilePath, "out", "", "", "Path to the output file, that's going to be encrypted and encoded in base64.")
	encryptCommand.MarkPersistentFlagRequired("public_key_path")
	rootCmd.AddCommand(encryptCommand)
}

var encryptCommand = &cobra.Command{
	Use:   "encrypt --public_key_path ./my-pubkey.pem --in ./mysecret.txt --out ./mysecret-enc.base64",
	Short: "Encrypt a file/value",
	Long:  "Encrypt a file/value using AES256-CBC symmetric encryption. Passfile runtime random generated and encrypted with RSA asymmetric keypair.",
	Run: func(_ *cobra.Command, _ []string) {
		var inFileContent []byte
		var err error
		if encryptInFilePath == "" {
			inFileContent, err = pkg.ReadFromStdin("Enter plaintext value to encrypt:")
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		} else {
			inFileContent, err = ioutil.ReadFile(encryptInFilePath)
			if err != nil {
				fmt.Printf("Error while reading file `in` at %s. Err: %s\n", encryptInFilePath, err)
				os.Exit(1)
			}
		}

		passphrase, err := encryption.GeneratePassphrase(16)
		if err != nil {
			fmt.Printf("Error while generating passphrase. Err: %s\n", err)
			os.Exit(1)
		}

		encryptedValue, encryptedPassphrase := encrypt(encryptPublicKeyPath, passphrase, inFileContent)

		fmt.Println("Encrypted passphrase below:")
		fmt.Println(encryptedPassphrase)
		if encryptOutFilePath == "" {
			fmt.Println()
			fmt.Println("Encrypted value below:")
			fmt.Println(encryptedValue)
		} else {
			err := ioutil.WriteFile(encryptOutFilePath, []byte(encryptedValue), 0644)

			if err != nil {
				fmt.Printf("Error while writing file `out` at %s. Err: %s\n", encryptOutFilePath, err)
				os.Exit(1)
			}
		}

		os.Exit(0)
	},
}

func encrypt(publicKeyPath string, passphrase, inFileContent []byte) (string, string) {
	publicKey, err := file.ReadPublicKeyFromPath(publicKeyPath)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	encryptedValue, err := encryption.Encrypt(passphrase, string(inFileContent))
	if err != nil {
		fmt.Printf("Error while encrypting file/value `in`. Err: %s\n", err)
		os.Exit(1)
	}

	encryptedPassphrase, err := encryption.EncryptPassphrase(publicKey, passphrase)
	if err != nil {
		fmt.Printf("Error while encrypting passphrase value. Err: %s\n", err)
		os.Exit(1)
	}

	return encryptedValue, encryptedPassphrase
}
