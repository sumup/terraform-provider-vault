package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/sumup/vault-encrypt-decrypt/encryption"
	"github.com/sumup/vault-encrypt-decrypt/pkg"
	"io/ioutil"
	"os"
	"github.com/sumup/vault-encrypt-decrypt/file"
)

var decryptPrivateKeyPath string
var decryptInFilePath string
var decryptOutFilePath string
var decryptEncryptedPassphrase string

func init() {
	decryptCommand.PersistentFlags().StringVarP(&decryptEncryptedPassphrase, "encrypted_passphrase", "", "", "Value of the encrypted and base64 encoded passphrase.")
	decryptCommand.PersistentFlags().StringVarP(&decryptPrivateKeyPath, "private_key_path", "", "", "Path to RSA private key used to decrypt passphrase at encrypted_passphrase")
	decryptCommand.PersistentFlags().StringVarP(&decryptInFilePath, "in", "", "", "Path to the input file.")
	decryptCommand.PersistentFlags().StringVarP(&decryptOutFilePath, "out", "", "", "Path to the output file, that's going to be decrypted.")
	decryptCommand.MarkPersistentFlagRequired("private_key_path")
	rootCmd.AddCommand(decryptCommand)
}

var decryptCommand = &cobra.Command{
	Use:   "decrypt --encrypted_passphrase <encrypted_passphrase> --private_key_path ./my-key.pem --in ./mysecret-enc.base64 --out ./mysecret.txt",
	Short: "Decrypt a file/value",
	Long:  "Decrypt a file/value using AES256-CBC symmetric encryption. Passphrase is encrypted with RSA asymmetric keypair.",
	Run: func(cmd *cobra.Command, args []string) {
		var inFileContent []byte
		var encryptedPassphrase []byte
		var err error

		if decryptEncryptedPassphrase == "" {
			encryptedPassphrase, err = pkg.ReadFromStdin("Enter encrypted passphrase:")
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		} else {
			encryptedPassphrase = []byte(decryptEncryptedPassphrase)
		}

		if decryptInFilePath == "" {
			inFileContent, err = pkg.ReadFromStdin("\nEnter encrypted value to decrypt:")
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		} else {
			inFileContent, err = ioutil.ReadFile(decryptInFilePath)
			if err != nil {
				fmt.Printf("Error while reading file `in` at %s. Err: %s\n", decryptInFilePath, err)
				os.Exit(1)
			}
		}

		decryptedValue := decrypt(decryptPrivateKeyPath, string(encryptedPassphrase), inFileContent)
		if decryptOutFilePath == "" {
			fmt.Println()
			fmt.Println("Decrypted value below:")
			fmt.Println(decryptedValue)
		} else {
			err = ioutil.WriteFile(decryptOutFilePath, []byte(decryptedValue), 0644)

			if err != nil {
				fmt.Printf("Error while writing file `out` at %s. Err: %s\n", decryptOutFilePath, err)
				os.Exit(1)
			}
		}

		os.Exit(0)
	},
}

func decrypt(privateKeyPath, encryptedPassphrase string, inFileContent []byte) string {
	privateKey, err := file.ReadPrivateKeyFromPath(privateKeyPath)
	if err != nil {
		fmt.Printf("Error while reading file `private_key_path` at %s. Err: %s\n", privateKeyPath, err)
		os.Exit(1)
	}

	passphrase, err := encryption.DecryptBase64Passphrase(privateKey, encryptedPassphrase)
	if err != nil {
		fmt.Printf("Error while decrypting passphrase. Err: %s\n", err)
		os.Exit(1)
	}

	decryptedValue, err := encryption.Decrypt(string(passphrase), string(inFileContent))

	if err != nil {
		fmt.Printf("Error while decrypting file/value `in` at %s. Err: %s\n", decryptInFilePath, err)
		os.Exit(1)
	}

	return decryptedValue
}
