package secretsencrypt

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/k3s-io/k3s/pkg/daemons/config"
	"github.com/k3s-io/k3s/pkg/version"
	corev1 "k8s.io/api/core/v1"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/config/v1"
)

const (
	EncryptionStart             string = "start"
	EncryptionPrepare           string = "prepare"
	EncryptionRotate            string = "rotate"
	EncryptionReencryptRequest  string = "reencrypt_request"
	EncryptionReencryptActive   string = "reencrypt_active"
	EncryptionReencryptFinished string = "reencrypt_finished"
	AESCBCKeyType               string = "aescbc"
	SecretBoxKeyType            string = "secretbox"
)

var EncryptionHashAnnotation = version.Program + ".io/encryption-config-hash"

func GetEncryptionProviders(runtime *config.ControlRuntime) ([]apiserverconfigv1.ProviderConfiguration, error) {
	curEncryptionByte, err := os.ReadFile(runtime.EncryptionConfig)
	if err != nil {
		return nil, err
	}

	curEncryption := apiserverconfigv1.EncryptionConfiguration{}
	if err = json.Unmarshal(curEncryptionByte, &curEncryption); err != nil {
		return nil, err
	}
	return curEncryption.Resources[0].Providers, nil
}

func GetEncryptionKeys(runtime *config.ControlRuntime) ([]apiserverconfigv1.Key, []apiserverconfigv1.Key, error) {

	providers, err := GetEncryptionProviders(runtime)
	if err != nil {
		return nil, nil, err
	}
	if len(providers) > 3 {
		return nil, nil, fmt.Errorf("more than 3 providers (%d) found in secrets encryption", len(providers))
	}

	var aescbcKeys []apiserverconfigv1.Key
	var sbKeys []apiserverconfigv1.Key
	for _, p := range providers {
		if p.AESCBC != nil {
			aescbcKeys = append(aescbcKeys, p.AESCBC.Keys...)
		}
		if p.Secretbox != nil {
			sbKeys = append(sbKeys, p.Secretbox.Keys...)
		}
		if p.AESGCM != nil || p.KMS != nil {
			return nil, nil, fmt.Errorf("unsupported encryption keys found")
		}
	}
	return aescbcKeys, sbKeys, nil
}

func WriteEncryptionConfig(runtime *config.ControlRuntime, AESCBCKeys []apiserverconfigv1.Key, SBKeys []apiserverconfigv1.Key, keyType string, enable bool) error {

	// Placing the identity provider first disables encryption
	var providers []apiserverconfigv1.ProviderConfiguration
	var primaryProvider apiserverconfigv1.ProviderConfiguration
	var secondaryProvider *apiserverconfigv1.ProviderConfiguration // May or may not be used
	switch keyType {
	case AESCBCKeyType:
		primaryProvider = apiserverconfigv1.ProviderConfiguration{
			AESCBC: &apiserverconfigv1.AESConfiguration{
				Keys: AESCBCKeys,
			},
		}
		if len(SBKeys) != 0 {
			secondaryProvider = &apiserverconfigv1.ProviderConfiguration{
				Secretbox: &apiserverconfigv1.SecretboxConfiguration{
					Keys: SBKeys,
				},
			}
		}
	case SecretBoxKeyType:
		primaryProvider = apiserverconfigv1.ProviderConfiguration{
			Secretbox: &apiserverconfigv1.SecretboxConfiguration{
				Keys: SBKeys,
			},
		}
		if len(AESCBCKeys) != 0 {
			secondaryProvider = &apiserverconfigv1.ProviderConfiguration{
				AESCBC: &apiserverconfigv1.AESConfiguration{
					Keys: AESCBCKeys,
				},
			}
		}
	}
	if enable {
		if secondaryProvider != nil {
			providers = []apiserverconfigv1.ProviderConfiguration{
				primaryProvider,
				*secondaryProvider,
				{
					Identity: &apiserverconfigv1.IdentityConfiguration{},
				},
			}
		} else {
			providers = []apiserverconfigv1.ProviderConfiguration{
				primaryProvider,
				{
					Identity: &apiserverconfigv1.IdentityConfiguration{},
				},
			}
		}
	} else {
		if secondaryProvider != nil {
			providers = []apiserverconfigv1.ProviderConfiguration{
				{
					Identity: &apiserverconfigv1.IdentityConfiguration{},
				},
				primaryProvider,
				*secondaryProvider,
			}
		} else {
			providers = []apiserverconfigv1.ProviderConfiguration{
				{
					Identity: &apiserverconfigv1.IdentityConfiguration{},
				},
				primaryProvider,
			}
		}
	}

	encConfig := apiserverconfigv1.EncryptionConfiguration{
		TypeMeta: metav1.TypeMeta{
			Kind:       "EncryptionConfiguration",
			APIVersion: "apiserver.config.k8s.io/v1",
		},
		Resources: []apiserverconfigv1.ResourceConfiguration{
			{
				Resources: []string{"secrets"},
				Providers: providers,
			},
		},
	}
	jsonfile, err := json.Marshal(encConfig)
	if err != nil {
		return err
	}
	return os.WriteFile(runtime.EncryptionConfig, jsonfile, 0600)
}

func GenEncryptionConfigHash(runtime *config.ControlRuntime) (string, error) {
	curEncryptionByte, err := os.ReadFile(runtime.EncryptionConfig)
	if err != nil {
		return "", err
	}
	encryptionConfigHash := sha256.Sum256(curEncryptionByte)
	return hex.EncodeToString(encryptionConfigHash[:]), nil
}

// GenReencryptHash generates a sha256 hash from the existing secrets keys and
// a new key based on the input arguments.
func GenReencryptHash(runtime *config.ControlRuntime, keyName string) (string, error) {

	aescbcKeys, sbKeys, err := GetEncryptionKeys(runtime)
	if err != nil {
		return "", err
	}
	newKey := apiserverconfigv1.Key{
		Name:   keyName,
		Secret: "12345",
	}
	keys := append(aescbcKeys, newKey)
	keys = append(sbKeys, newKey)
	b, err := json.Marshal(keys)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:]), nil
}

func getEncryptionHashFile(runtime *config.ControlRuntime) (string, error) {
	curEncryptionByte, err := os.ReadFile(runtime.EncryptionHash)
	if err != nil {
		return "", err
	}
	return string(curEncryptionByte), nil
}

func BootstrapEncryptionHashAnnotation(node *corev1.Node, runtime *config.ControlRuntime) error {
	existingAnn, err := getEncryptionHashFile(runtime)
	if err != nil {
		return err
	}
	node.Annotations[EncryptionHashAnnotation] = existingAnn
	return nil
}

func WriteEncryptionHashAnnotation(runtime *config.ControlRuntime, node *corev1.Node, stage string) error {
	encryptionConfigHash, err := GenEncryptionConfigHash(runtime)
	if err != nil {
		return err
	}
	if node.Annotations == nil {
		return fmt.Errorf("node annotations do not exist for %s", node.ObjectMeta.Name)
	}
	ann := stage + "-" + encryptionConfigHash
	node.Annotations[EncryptionHashAnnotation] = ann
	if _, err = runtime.Core.Core().V1().Node().Update(node); err != nil {
		return err
	}
	logrus.Debugf("encryption hash annotation set successfully on node: %s\n", node.ObjectMeta.Name)
	return os.WriteFile(runtime.EncryptionHash, []byte(ann), 0600)
}
