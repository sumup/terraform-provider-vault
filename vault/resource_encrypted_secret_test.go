package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/sumup/vault-encrypt-decrypt/encryption"
	"github.com/sumup/vault-encrypt-decrypt/file"
	"log"
)

const dataJson = `{
    "hello": "world"
}`

func TestResourceEncryptedSecret_initial(t *testing.T) {
	publicKeyPath, privateKeyPath := getTestPublicAndPrivateKeysAndPassfilePaths(t)

	publicKey, err := file.ReadPublicKeyFromPath(publicKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	privateKey, err := file.ReadPrivateKeyFromPath(privateKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	passphrase, err := encryption.GeneratePassphrase(16)
	if err != nil {
		log.Fatal(err)
	}

	path := acctest.RandomWithPrefix("secret/encrypted_test")
	encryptedValue, err := encryption.Encrypt(passphrase, dataJson)
	if err != nil {
		log.Fatal(err)
	}

	encryptedPassphrase, err := encryption.EncryptPassphrase(publicKey, passphrase)
	if err != nil {
		log.Fatal(err)
	}

	// NOTE: Sanity check that the passphrase is decryptable
	_, err = encryption.DecryptBase64Passphrase(privateKey, encryptedPassphrase)
	if err != nil {
		log.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccVaultEncryptedSecretCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceEncryptedSecret_initialConfig(path, encryptedValue, encryptedPassphrase),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_encrypted_secret.test",
						"path", path),
					resource.TestCheckResourceAttr("vault_encrypted_secret.test",
						"encrypted_data_json", encryptedValue),
					resource.TestCheckResourceAttr("vault_encrypted_secret.test",
						"encrypted_passphrase", encryptedPassphrase),
				),
			},
		},
	})
}

func TestResourceEncryptedSecret_updated(t *testing.T) {
	publicKeyPath, privateKeyPath := getTestPublicAndPrivateKeysAndPassfilePaths(t)

	publicKey, err := file.ReadPublicKeyFromPath(publicKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	privateKey, err := file.ReadPrivateKeyFromPath(privateKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	passphrase, err := encryption.GeneratePassphrase(16)
	if err != nil {
		log.Fatal(err)
	}

	path := acctest.RandomWithPrefix("secret/encrypted_test")
	oldEncryptedValue, err := encryption.Encrypt(passphrase, dataJson)
	if err != nil {
		log.Fatal(err)
	}

	newEncryptedValue, err := encryption.Encrypt(passphrase, dataJson)
	if err != nil {
		log.Fatal(err)
	}

	encryptedPassphrase, err := encryption.EncryptPassphrase(publicKey, passphrase)
	if err != nil {
		log.Fatal(err)
	}

	// NOTE: Sanity check that the passphrase is decryptable
	_, err = encryption.DecryptBase64Passphrase(privateKey, encryptedPassphrase)
	if err != nil {
		log.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccVaultEncryptedSecretCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceEncryptedSecret_initialConfig(path, oldEncryptedValue, encryptedPassphrase),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_encrypted_secret.test",
						"path", path),
					resource.TestCheckResourceAttr("vault_encrypted_secret.test",
						"encrypted_data_json", oldEncryptedValue),
					resource.TestCheckResourceAttr("vault_encrypted_secret.test",
						"encrypted_passphrase", encryptedPassphrase),
				),
			},
			{
				Config: testResourceEncryptedSecret_initialConfig(path, newEncryptedValue, encryptedPassphrase),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_encrypted_secret.test",
						"path", path),
					resource.TestCheckResourceAttr("vault_encrypted_secret.test",
						"encrypted_data_json", newEncryptedValue),
					resource.TestCheckResourceAttr("vault_encrypted_secret.test",
						"encrypted_passphrase", encryptedPassphrase),
				),
			},
		},
	})
}

func testAccVaultEncryptedSecretCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*EncryptedClient)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_encrypted_secret" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for vault encrypted secret %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("vault encrypted secret %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testResourceEncryptedSecret_initialConfig(path, encryptedDataJSON, encryptedPassphrase string) string {
	return fmt.Sprintf(`
resource "vault_encrypted_secret" "test" {
    path = "%s"
    encrypted_data_json = "%s"
    encrypted_passphrase = "%s"
}`, path, encryptedDataJSON, encryptedPassphrase)
}

func testResourceEncryptedSecret_initialCheck(expectedPath, dataJsonKey, dataJsonValue string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_encrypted_secret.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		path := instanceState.ID

		if path != instanceState.Attributes["path"] {
			return fmt.Errorf("id doesn't match path")
		}
		if path != expectedPath {
			return fmt.Errorf("unexpected secret path")
		}

		client := testProvider.Meta().(*EncryptedClient)
		secret, err := client.Logical().Read(path)
		if err != nil {
			return fmt.Errorf("error reading back secret: %s", err)
		}

		if got := secret.Data[dataJsonKey]; got != dataJsonValue {
			return fmt.Errorf("'%s' data is %v; want %q", dataJsonKey, got, dataJsonValue)
		}

		return nil
	}
}
