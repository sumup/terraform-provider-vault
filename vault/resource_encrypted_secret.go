package vault

import (
	"encoding/json"
	"fmt"
	"log"

	"encoding/base64"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/sumup/vault-encrypt-decrypt/encryption"
)

func encryptedSecretResource() *schema.Resource {
	return &schema.Resource{
		SchemaVersion: 1,
		Create:        encryptedSecretResourceWrite,
		Update:        encryptedSecretResourceWrite,
		Delete:        encryptedSecretResourceDelete,
		Read:          encryptedSecretResourceRead,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Full path where the encrypted secret will be written.",
			},
			"encrypted_data_json": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Encrypted, base64-encoded and JSON-encoded secret data to write.",
				ValidateFunc: ValidateBase64,
				StateFunc:    trimStringStateFunc,
				Sensitive:    true,
			},
			"encrypted_passphrase": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Encrypted and base64-encoded passphrase for `encrypted_data_json`.",
				ValidateFunc: ValidateBase64,
				StateFunc:    trimStringStateFunc,
				Sensitive:    true,
			},
		},
	}
}

func ValidateBase64(dataInterface interface{}, _ string) ([]string, []error) {
	data := dataInterface.(string)
	_, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, []error{err}
	}
	return nil, nil
}

func encryptedSecretResourceWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*EncryptedClient)

	path := d.Get("path").(string)

	var data map[string]interface{}
	encryptedPassphrase := d.Get("encrypted_passphrase").(string)
	passphrase, err := encryption.DecryptBase64Passphrase(client.privateKey, encryptedPassphrase)
	if err != nil {
		return fmt.Errorf("unable to decrypt encrypted passphrase %s. Err: %s", encryptedPassphrase, err)
	}

	encryptedDataJSON := d.Get("encrypted_data_json").(string)
	decryptedValue, err := encryption.Decrypt(string(passphrase), encryptedDataJSON)
	if err != nil {
		return fmt.Errorf("unable to decrypt encrypted value at %s. Err: %s", path, err)
	}

	err = json.Unmarshal([]byte(decryptedValue), &data)
	if err != nil {
		return fmt.Errorf("unable to unmarshal encrypted_data_json: %s. Syntax error: %s", encryptedDataJSON, err)
	}

	log.Printf("[DEBUG] Writing encrypted Vault secret to %s", path)
	_, err = client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}

	d.SetId(path)

	return encryptedSecretResourceRead(d, meta)
}

func encryptedSecretResourceDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*EncryptedClient)

	path := d.Id()

	log.Printf("[DEBUG] Deleting vault_encrypted_secret from %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting %q from Vault: %q", path, err)
	}

	return nil
}

func encryptedSecretResourceRead(_ *schema.ResourceData, _ interface{}) error {
	// NOTE: Don't read back since,
	// we're using encrypted payload already.
	// Reading it back and storing it would need a re-encryption again,
	// which would result in a diff.
	return nil
}
