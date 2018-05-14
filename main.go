package main

import (
	"github.com/hashicorp/terraform/plugin"
	"github.com/sumup/terraform-provider-vault/vault"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: vault.Provider})
}
