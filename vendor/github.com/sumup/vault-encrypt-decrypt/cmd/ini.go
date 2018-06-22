package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/hashicorp/hcl/hcl/printer"
	"github.com/hashicorp/hcl/json/parser"
	"github.com/spf13/cobra"
	"github.com/sumup/vault-encrypt-decrypt/encryption"
	"github.com/go-ini/ini"
	"os"
	"strings"
)

var iniPublicKeyPath string
var iniPrivateKeyPath string
var iniInFilePath string
var iniOutFilePath string
var iniEncryptedPassfilePath string

func init() {
	iniCommand.PersistentFlags().StringVarP(&iniPublicKeyPath, "public_key_path", "", "", "Path to RSA public key used to encrypt runtime random generated passphrase.")
	iniCommand.PersistentFlags().StringVarP(&iniPrivateKeyPath, "private_key_path", "", "", "Path to RSA private key used to decrypt encrypted passphrase.")
	iniCommand.PersistentFlags().StringVarP(&iniInFilePath, "in", "", "", "Path to the input INI file")
	iniCommand.PersistentFlags().StringVarP(&iniOutFilePath, "out", "", "", "Path to the output terraform file")
	iniCommand.MarkPersistentFlagRequired("public_key_path")
	iniCommand.MarkPersistentFlagRequired("in")
	iniCommand.MarkPersistentFlagRequired("out")
	rootCmd.AddCommand(iniCommand)
}

// NOTE: This is only a temporary functionality
// until all ini files are converted to terraform resources.
var iniCommand = &cobra.Command{
	Use:   "ini --public_key_path ./my-key.pem --private_key_path ./my-pubkey.pem --in ./secrets.ini --out ./secrets.tf",
	Short: "Convert an INI file to Terraform file",
	Long:  "Convert an INI file to Terraform file with vault_encrypted_secret resources, encrypted with AES256-CBC symmetric encryption. Passfile runtime random generated and encrypted with RSA asymmetric keypair.",
	Run: func(_ *cobra.Command, _ []string) {
		iniFile, err := readINI(iniInFilePath)
		if err != nil {
			fmt.Printf("Failed to read INI file. Err: %s\n", err)
			os.Exit(1)
		}

		iniMap := parseINIfileContents(iniFile)
		terraformMap, _ := convertIniContentToTerraformContent(iniMap)
		hclFile, err := terraformContentToHCLfile(terraformMap)

		if err != nil {
			fmt.Printf("Failed to transform map with terraform resources to HCL: Err: %s\n", err)
			os.Exit(1)
		}

		err = writeHCLfile(hclFile, iniOutFilePath)

		if err != nil {
			fmt.Printf("Failed to write HCL to file. Err: %s\n", err)
			os.Exit(1)
		}
	},
}

func readINI(path string) (*ini.File, error) {
	cfg, err := ini.LoadSources(ini.LoadOptions{AllowPythonMultilineValues: true, SpaceBeforeInlineComment: true}, path)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

type IniContent struct {
	SectionsByName map[string]*IniSection
}

func NewIniContent() *IniContent {
	return &IniContent{map[string]*IniSection{}}
}

type IniSection struct {
	Name   string
	Values []*IniSectionValue
}

func NewIniSection(name string) *IniSection {
	return &IniSection{name, []*IniSectionValue{}}
}

func (content *IniContent) AddSection(section *IniSection) {
	content.SectionsByName[section.Name] = section
	return
}

type IniSectionValue struct {
	KeyName string
	Value   interface{}
}

func NewIniSectionValue(key string, value interface{}) *IniSectionValue {
	return &IniSectionValue{key, value}
}

func parseINIfileContents(file *ini.File) *IniContent {
	iniContent := NewIniContent()

	for _, section := range file.Sections() {
		// NOTE: Default section by the INI parser is `DEFAULT`.
		if section.Name() == "DEFAULT" {
			continue
		}

		iniSection := NewIniSection(section.Name())

		for _, sectionKey := range section.Keys() {
			iniSection.Values = append(iniSection.Values, NewIniSectionValue(sectionKey.Name(), sectionKey.Value()))
		}

		iniContent.AddSection(iniSection)
	}
	return iniContent
}

type TerraformContent struct {
	ResourcesByName map[string]*TerraformResource
}

func NewTerraformContent() *TerraformContent {
	return &TerraformContent{map[string]*TerraformResource{}}
}

func (content *TerraformContent) AddResource(resource *TerraformResource) {
	content.ResourcesByName[resource.Name] = resource
	return
}

type TerraformResource struct {
	Name    string
	Type    string
	Content map[string]string
}

func NewTerraformResource(name string, resourceType string) *TerraformResource {
	return &TerraformResource{name, resourceType, map[string]string{}}
}

func convertIniContentToTerraformContent(iniContent *IniContent) (*TerraformContent, error) {
	terraformContent := NewTerraformContent()

	for name, section := range iniContent.SectionsByName {
		for _, sectionValue := range section.Values {
			resourceName := fmt.Sprintf("%s/%s", name, sectionValue.KeyName)
			terraformResource := NewTerraformResource(
				fmt.Sprintf("vault_encrypted_secret_%s", strings.Replace(resourceName, "/", "_", -1)),
				"vault_encrypted_secret",
			)

			valueMap := map[string]interface{}{
				"value": sectionValue.Value,
			}

			dataJson, err := json.Marshal(valueMap)

			if err != nil {
				return nil, err
			}

			passphrase, err := encryption.GeneratePassphrase(16)
			if err != nil {
				fmt.Printf("Error while generating passphrase. Err: %s\n", err)
				os.Exit(1)
			}
			encryptedDataJson, encryptedPassphrase := encrypt(iniPublicKeyPath, passphrase, dataJson)

			path := fmt.Sprintf("secret/%s", resourceName)
			terraformResource.Content = map[string]string{
				"path":                 path,
				"encrypted_data_json":  string(encryptedDataJson),
				"encrypted_passphrase": string(encryptedPassphrase),
			}
			// NOTE: Do a sanity check just in case the encryption/decryption may be problematic.
			decryptedValue := decrypt(iniPrivateKeyPath, encryptedPassphrase, []byte(encryptedDataJson))
			if string(dataJson) != decryptedValue {
				fmt.Printf("Mismatching encrypted/decrypted value for path %s\n", path)
				os.Exit(1)
			}

			terraformContent.AddResource(terraformResource)
		}
	}

	return terraformContent, nil
}

func terraformContentToHCLfile(terraformContent *TerraformContent) (*ast.File, error) {
	resourceContentByName := map[string]map[string]string{}

	for resourceName, resource := range terraformContent.ResourcesByName {
		resourceContentByName[resourceName] = resource.Content
	}

	terraformMap := map[string]map[string]map[string]map[string]string{}
	terraformMap["resource"] = map[string]map[string]map[string]string{
		"vault_encrypted_secret": resourceContentByName,
	}
	terraformMapBytes, err := json.Marshal(terraformMap)

	if err != nil {
		return nil, err
	}

	hclAST, err := parser.Parse(terraformMapBytes)

	if err != nil {
		return nil, err
	}

	return hclAST, nil
}

func writeHCLfile(hclFile *ast.File, filePath string) error {
	fileDescriptor, err := os.Create(filePath)
	if err != nil {
		return err
	}

	fileWriter := bufio.NewWriter(fileDescriptor)
	return printer.Fprint(fileWriter, hclFile)
}
