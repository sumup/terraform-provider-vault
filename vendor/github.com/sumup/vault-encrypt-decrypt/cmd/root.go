package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

var rootCmd = &cobra.Command{
	Use:   "vault-encrypt-decrypt",
	Short: "Vault encrypt/decrypt cli utility",
	Long:  "Encrypt/decrypt secrets for Vault via symmetric AES256-CBC. Passfile is encrypted/decrypted via RSA asymmetric keypair.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Use `--help` to see available commands")
		os.Exit(0)
	},
}

func Execute() {
	rootCmd.SetVersionTemplate(Version)
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
