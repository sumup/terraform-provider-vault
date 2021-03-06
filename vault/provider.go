package vault

import (
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"crypto/rsa"
	"github.com/hashicorp/terraform/helper/logging"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/go-homedir"
	"github.com/sumup/vault-encrypt-decrypt/file"
)

func Provider() terraform.ResourceProvider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"address": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_ADDR", nil),
				Description: "URL of the root of the target Vault server.",
			},
			"token": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_TOKEN", ""),
				Description: "Token to use to authenticate to Vault.",
			},
			"private_key_path": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_PRIVATE_KEY_PATH", ""),
				Description: "Path to private key used to decrypt `encrypted_passfile_path`.",
			},
			"ca_cert_file": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_CACERT", ""),
				Description: "Path to a CA certificate file to validate the server's certificate.",
			},
			"ca_cert_dir": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_CAPATH", ""),
				Description: "Path to directory containing CA certificate files to validate the server's certificate.",
			},
			"client_auth": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Client authentication credentials.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"cert_file": {
							Type:        schema.TypeString,
							Required:    true,
							DefaultFunc: schema.EnvDefaultFunc("VAULT_CLIENT_CERT", ""),
							Description: "Path to a file containing the client certificate.",
						},
						"key_file": {
							Type:        schema.TypeString,
							Required:    true,
							DefaultFunc: schema.EnvDefaultFunc("VAULT_CLIENT_KEY", ""),
							Description: "Path to a file containing the private key that the certificate was issued for.",
						},
					},
				},
			},
			"skip_tls_verify": {
				Type:        schema.TypeBool,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_SKIP_VERIFY", ""),
				Description: "Set this to true only if the target Vault server is an insecure development instance.",
			},
			"max_lease_ttl_seconds": {
				Type:     schema.TypeInt,
				Optional: true,

				// Default is 20min, which is intended to be enough time for
				// a reasonable Terraform run can complete but not
				// significantly longer, so that any leases are revoked shortly
				// after Terraform has finished running.
				DefaultFunc: schema.EnvDefaultFunc("TERRAFORM_VAULT_MAX_TTL", 1200),

				Description: "Maximum TTL for secret leases requested by this provider",
			},
		},

		ConfigureFunc: providerConfigure,

		DataSourcesMap: map[string]*schema.Resource{
			"vault_approle_auth_backend_role_id":   approleAuthBackendRoleIDDataSource(),
			"vault_kubernetes_auth_backend_config": kubernetesAuthBackendConfigDataSource(),
			"vault_kubernetes_auth_backend_role":   kubernetesAuthBackendRoleDataSource(),
			"vault_aws_access_credentials":         awsAccessCredentialsDataSource(),
			"vault_generic_secret":                 genericSecretDataSource(),
		},

		ResourcesMap: map[string]*schema.Resource{
			"vault_approle_auth_backend_login":          approleAuthBackendLoginResource(),
			"vault_approle_auth_backend_role":           approleAuthBackendRoleResource(),
			"vault_approle_auth_backend_role_secret_id": approleAuthBackendRoleSecretIDResource(),
			"vault_auth_backend":                        authBackendResource(),
			"vault_aws_auth_backend_cert":               awsAuthBackendCertResource(),
			"vault_aws_auth_backend_client":             awsAuthBackendClientResource(),
			"vault_aws_auth_backend_identity_whitelist": awsAuthBackendIdentityWhitelistResource(),
			"vault_aws_auth_backend_login":              awsAuthBackendLoginResource(),
			"vault_aws_auth_backend_role":               awsAuthBackendRoleResource(),
			"vault_aws_auth_backend_role_tag":           awsAuthBackendRoleTagResource(),
			"vault_aws_auth_backend_sts_role":           awsAuthBackendSTSRoleResource(),
			"vault_aws_secret_backend":                  awsSecretBackendResource(),
			"vault_aws_secret_backend_role":             awsSecretBackendRoleResource(),
			"vault_database_secret_backend_connection":  databaseSecretBackendConnectionResource(),
			"vault_database_secret_backend_role":        databaseSecretBackendRoleResource(),
			"vault_generic_secret":                      genericSecretResource(),
			"vault_encrypted_secret":                    encryptedSecretResource(),
			"vault_kubernetes_auth_backend_config":      kubernetesAuthBackendConfigResource(),
			"vault_kubernetes_auth_backend_role":        kubernetesAuthBackendRoleResource(),
			"vault_okta_auth_backend":                   oktaAuthBackendResource(),
			"vault_okta_auth_backend_user":              oktaAuthBackendUserResource(),
			"vault_okta_auth_backend_group":             oktaAuthBackendGroupResource(),
			"vault_policy":                              policyResource(),
			"vault_mount":                               mountResource(),
		},
	}
}

type EncryptedClient struct {
	api.Client
	privateKey *rsa.PrivateKey
}

func NewEncryptedClient(client *api.Client, privateKey *rsa.PrivateKey) *EncryptedClient {
	return &EncryptedClient{
		*client,
		privateKey,
	}
}

func providerConfigure(d *schema.ResourceData) (interface{}, error) {
	config := api.DefaultConfig()
	config.Address = d.Get("address").(string)

	clientAuthI := d.Get("client_auth").([]interface{})
	if len(clientAuthI) > 1 {
		return nil, fmt.Errorf("client_auth block may appear only once")
	}

	clientAuthCert := ""
	clientAuthKey := ""
	if len(clientAuthI) == 1 {
		clientAuth := clientAuthI[0].(map[string]interface{})
		clientAuthCert = clientAuth["cert_file"].(string)
		clientAuthKey = clientAuth["key_file"].(string)
	}

	err := config.ConfigureTLS(&api.TLSConfig{
		CACert:   d.Get("ca_cert_file").(string),
		CAPath:   d.Get("ca_cert_dir").(string),
		Insecure: d.Get("skip_tls_verify").(bool),

		ClientCert: clientAuthCert,
		ClientKey:  clientAuthKey,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to configure TLS for Vault API: %s", err)
	}

	config.HttpClient.Transport = logging.NewTransport("Vault", config.HttpClient.Transport)

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to configure Vault API: %s", err)
	}

	token := d.Get("token").(string)
	if token == "" {
		// Use the vault CLI's token, if present.
		homePath, err := homedir.Dir()
		if err != nil {
			return nil, fmt.Errorf("Can't find home directory when looking for ~/.vault-token: %s", err)
		}
		tokenBytes, err := ioutil.ReadFile(homePath + "/.vault-token")
		if err != nil {
			return nil, fmt.Errorf("No vault token found: %s", err)
		}

		token = strings.TrimSpace(string(tokenBytes))
	}

	var privateKey *rsa.PrivateKey
	privateKeyPathTypeless := d.Get("private_key_path")
	switch privateKeyPathTypeless.(type) {
	case string:
		privateKeyPath := privateKeyPathTypeless.(string)
		if privateKeyPath != "" {
			key, err := file.ReadPrivateKeyFromPath(privateKeyPath)
			if err != nil {
				return nil, err
			}

			privateKey = key
		}
	default:
		return nil, fmt.Errorf("non-string private_key_path")
	}

	// In order to enforce our relatively-short lease TTL, we derive a
	// temporary child token that inherits all of the policies of the
	// token we were given but expires after max_lease_ttl_seconds.
	//
	// The intent here is that Terraform will need to re-fetch any
	// secrets on each run and so we limit the exposure risk of secrets
	// that end up stored in the Terraform state, assuming that they are
	// credentials that Vault is able to revoke.
	//
	// Caution is still required with state files since not all secrets
	// can explicitly be revoked, and this limited scope won't apply to
	// any secrets that are *written* by Terraform to Vault.

	client.SetToken(token)
	renewable := false
	childTokenLease, err := client.Auth().Token().Create(&api.TokenCreateRequest{
		DisplayName:    "terraform",
		TTL:            fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds").(int)),
		ExplicitMaxTTL: fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds").(int)),
		Renewable:      &renewable,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create limited child token: %s", err)
	}

	childToken := childTokenLease.Auth.ClientToken
	policies := childTokenLease.Auth.Policies

	log.Printf("[INFO] Using Vault token with the following policies: %s", strings.Join(policies, ", "))

	client.SetToken(childToken)

	return NewEncryptedClient(client, privateKey), nil
}
