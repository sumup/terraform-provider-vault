package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
)

func TestAccAWSAuthBackendClient_import(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckAWSAuthBackendClientDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendClientConfig_basic(backend),
				Check:  testAccAWSAuthBackendClientCheck_attrs(backend),
			},
			{
				ResourceName:      "vault_aws_auth_backend_client.client",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccAWSAuthBackendClient_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccCheckAWSAuthBackendClientDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendClientConfig_basic(backend),
				Check:  testAccAWSAuthBackendClientCheck_attrs(backend),
			},
			{
				Config: testAccAWSAuthBackendClientConfig_updated(backend),
				Check:  testAccAWSAuthBackendClientCheck_attrs(backend),
			},
		},
	})
}

func testAccCheckAWSAuthBackendClientDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*EncryptedClient)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_aws_auth_backend_client" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("Error checking for AWS auth backend %q client config: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("AWS auth backend %q still configured", rs.Primary.ID)
		}
	}
	return nil
}

func testAccAWSAuthBackendClientConfig_basic(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "%s"
  description = "Test auth backend for AWS backend client config"
}

resource "vault_aws_auth_backend_client" "client" {
  backend = "${vault_auth_backend.aws.path}"
  access_key = "AWSACCESSKEY"
  secret_key = "AWSSECRETKEY"
  ec2_endpoint = "http://vault.test/ec2"
  iam_endpoint = "http://vault.test/iam"
  sts_endpoint = "http://vault.test/sts"
  iam_server_id_header_value = "vault.test"
}
`, backend)
}

func testAccAWSAuthBackendClientCheck_attrs(backend string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_aws_auth_backend_client.client"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		endpoint := instanceState.ID

		if endpoint != "auth/"+backend+"/config/client" {
			return fmt.Errorf("expected ID to be %q, got %q", "auth/"+backend+"/config/client", endpoint)
		}

		client := testProvider.Meta().(*EncryptedClient)
		resp, err := client.Logical().Read(endpoint)
		if err != nil {
			return fmt.Errorf("error reading back AWS auth client config from %q: %s", endpoint, err)
		}
		if resp == nil {
			return fmt.Errorf("AWS auth client not configured at %q", endpoint)
		}
		attrs := map[string]string{
			"access_key":                 "access_key",
			"secret_key":                 "secret_key",
			"ec2_endpoint":               "endpoint",
			"iam_endpoint":               "iam_endpoint",
			"sts_endpoint":               "sts_endpoint",
			"iam_server_id_header_value": "iam_server_id_header_value",
		}
		for stateAttr, apiAttr := range attrs {
			if resp.Data[apiAttr] == nil && instanceState.Attributes[stateAttr] == "" {
				continue
			}
			if resp.Data[apiAttr] != instanceState.Attributes[stateAttr] {
				return fmt.Errorf("Expected %s (%s) of %q to be %q, got %q", apiAttr, stateAttr, endpoint, instanceState.Attributes[stateAttr], resp.Data[apiAttr])
			}
		}
		return nil
	}
}

func testAccAWSAuthBackendClientConfig_updated(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  path = "%s"
  type = "aws"
  description = "Test auth backend for AWS backend client config"
}

resource "vault_aws_auth_backend_client" "client" {
  backend = "${vault_auth_backend.aws.path}"
  access_key = "UPDATEDAWSACCESSKEY"
  secret_key = "UPDATEDAWSSECRETKEY"
  ec2_endpoint = "http://upadted.vault.test/ec2"
  iam_endpoint = "http://updated.vault.test/iam"
  sts_endpoint = "http://updated.vault.test/sts"
  iam_server_id_header_value = "updated.vault.test"
}`, backend)
}
