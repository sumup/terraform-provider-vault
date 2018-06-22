package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

var Version = "0.5.0"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of vault-encrypt-decrypt",
	Long:  `Print the version of vault-encrypt-decrypt.`,
	Run: func(command *cobra.Command, args []string) {
		fmt.Println("vault-encrypt-decrypt version:", Version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
