package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
)

func awsAuthBackendClientResource() *schema.Resource {
	return &schema.Resource{
		Create: awsAuthBackendWrite,
		Read:   awsAuthBackendRead,
		Update: awsAuthBackendWrite,
		Delete: awsAuthBackendDelete,
		Exists: awsAuthBackendExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Unique name of the auth backend to configure.",
				ForceNew:    true,
				Default:     "aws",
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			"access_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "AWS Access key with permissions to query AWS APIs.",
				Sensitive:   true,
			},
			"secret_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "AWS Secret key with permissions to query AWS APIs.",
				Sensitive:   true,
			},
			"ec2_endpoint": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "URL to override the default generated endpoint for making AWS EC2 API calls.",
			},
			"iam_endpoint": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "URL to override the default generated endpoint for making AWS IAM API calls.",
			},
			"sts_endpoint": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "URL to override the default generated endpoint for making AWS STS API calls.",
			},
			"iam_server_id_header_value": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The value to require in the X-Vault-AWS-IAM-Server-ID header as part of GetCallerIdentity requests that are used in the iam auth method.",
			},
		},
	}
}

func awsAuthBackendWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*EncryptedClient)

	// if backend comes from the config, it won't have the StateFunc
	// applied yet, so we need to apply it again.
	backend := d.Get("backend").(string)
	accessKey := d.Get("access_key").(string)
	secretKey := d.Get("secret_key").(string)
	ec2Endpoint := d.Get("ec2_endpoint").(string)
	iamEndpoint := d.Get("iam_endpoint").(string)
	stsEndpoint := d.Get("sts_endpoint").(string)
	iamServerIDHeaderValue := d.Get("iam_server_id_header_value").(string)

	path := awsAuthBackendClientPath(backend)

	data := map[string]interface{}{
		"access_key":                 accessKey,
		"secret_key":                 secretKey,
		"endpoint":                   ec2Endpoint,
		"iam_endpoint":               iamEndpoint,
		"sts_endpoint":               stsEndpoint,
		"iam_server_id_header_value": iamServerIDHeaderValue,
	}

	log.Printf("[DEBUG] Writing AWS auth backend client config to %q", path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error writing to %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote AWS auth backend client config to %q", path)

	d.SetId(path)

	return awsAuthBackendRead(d, meta)
}

func awsAuthBackendRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*EncryptedClient)

	log.Printf("[DEBUG] Reading AWS auth backend client config")
	secret, err := client.Logical().Read(d.Id())
	if err != nil {
		return fmt.Errorf("Error reading AWS auth backend client config from %q: %s", d.Id(), err)
	}
	log.Printf("[DEBUG] Read AWS auth backend client config")

	if secret == nil {
		log.Printf("[WARN] No info found at %q; removing from state.", d.Id())
		d.SetId("")
		return nil
	}
	idPieces := strings.Split(d.Id(), "/")
	if len(idPieces) != 4 {
		return fmt.Errorf("expected %q to have 4 pieces, has %d", d.Id(), len(idPieces))
	}
	d.Set("backend", idPieces[1])
	d.Set("access_key", secret.Data["access_key"])
	d.Set("secret_key", secret.Data["secret_key"])
	d.Set("ec2_endpoint", secret.Data["endpoint"])
	d.Set("iam_endpoint", secret.Data["iam_endpoint"])
	d.Set("sts_endpoint", secret.Data["sts_endpoint"])
	d.Set("iam_server_id_header_value", secret.Data["iam_server_id_header_value"])
	return nil
}

func awsAuthBackendDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*EncryptedClient)

	log.Printf("[DEBUG] Deleting AWS auth backend client config from %q", d.Id())
	_, err := client.Logical().Delete(d.Id())
	if err != nil {
		return fmt.Errorf("Error deleting AWS auth backend client config from %q: %s", d.Id(), err)
	}
	log.Printf("[DEBUG] Deleted AWS auth backend client config from %q", d.Id())

	return nil
}

func awsAuthBackendExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*EncryptedClient)

	log.Printf("[DEBUG] Checking if AWS auth backend client is configured at %q", d.Id())
	secret, err := client.Logical().Read(d.Id())
	if err != nil {
		return true, fmt.Errorf("Error checking if AWS auth backend client is configured at %q: %s", d.Id(), err)
	}
	log.Printf("[DEBUG] Checked if AWS auth backend client is configured at %q", d.Id())
	return secret != nil, nil
}

func awsAuthBackendClientPath(path string) string {
	return "auth/" + strings.Trim(path, "/") + "/config/client"
}
