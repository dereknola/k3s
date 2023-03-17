package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/k3s-io/k3s/pkg/cluster"
	"github.com/k3s-io/k3s/pkg/daemons/config"
	"github.com/k3s-io/k3s/pkg/secretsencrypt"
	"github.com/rancher/wrangler/pkg/generated/controllers/core"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/config/v1"
	"k8s.io/utils/pointer"
)

const (
	aescbcKeySize    = 32
	secretBoxKeySize = 32
)

type EncryptionState struct {
	Stage        string   `json:"stage"`
	ActiveKey    string   `json:"activekey"`
	Enable       *bool    `json:"enable,omitempty"`
	HashMatch    bool     `json:"hashmatch,omitempty"`
	HashError    string   `json:"hasherror,omitempty"`
	InactiveKeys []string `json:"inactivekeys,omitempty"`
}

type EncryptionRequest struct {
	Stage   *string `json:"stage,omitempty"`
	KeyType *string `json:"keytype,omitempty"`
	Enable  *bool   `json:"enable,omitempty"`
	Force   bool    `json:"force"`
	Skip    bool    `json:"skip"`
}

func getEncryptionRequest(req *http.Request) (EncryptionRequest, error) {
	b, err := io.ReadAll(req.Body)
	if err != nil {
		return EncryptionRequest{}, err
	}
	result := EncryptionRequest{}
	err = json.Unmarshal(b, &result)
	return result, err
}

func encryptionStatusHandler(server *config.Control) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		if req.TLS == nil {
			resp.WriteHeader(http.StatusNotFound)
			return
		}
		status, err := encryptionStatus(server)
		if err != nil {
			genErrorMessage(resp, http.StatusInternalServerError, err, "secrets-encrypt")
			return
		}
		b, err := json.Marshal(status)
		if err != nil {
			genErrorMessage(resp, http.StatusInternalServerError, err, "secrets-encrypt")
			return
		}
		resp.Write(b)
	})
}

func encryptionStatus(server *config.Control) (EncryptionState, error) {
	state := EncryptionState{}
	providers, err := secretsencrypt.GetEncryptionProviders(server.Runtime)
	if os.IsNotExist(err) {
		return state, nil
	} else if err != nil {
		return state, err
	}
	if providers[len(providers)-1].Identity != nil && (providers[0].AESCBC != nil || providers[0].Secretbox != nil) {
		state.Enable = pointer.Bool(true)
	} else if !server.EncryptSecrets || providers[0].Identity != nil && (providers[1].AESCBC != nil || providers[1].Secretbox != nil) {
		state.Enable = pointer.Bool(false)
	}

	if err := verifyEncryptionHashAnnotation(server.Runtime, server.Runtime.Core.Core(), ""); err != nil {
		state.HashMatch = false
		state.HashError = err.Error()
	} else {
		state.HashMatch = true
	}
	stage, _, err := getEncryptionHashAnnotation(server.Runtime.Core.Core())
	if err != nil {
		return state, err
	}
	state.Stage = stage
	active := true
	for _, p := range providers {
		if p.AESCBC != nil {
			for _, aesKey := range p.AESCBC.Keys {
				typName := "AES-CBC " + aesKey.Name
				if active {
					active = false
					state.ActiveKey = typName
				} else {
					state.InactiveKeys = append(state.InactiveKeys, typName)
				}
			}
		}
		if p.Secretbox != nil {
			for _, sbKey := range p.Secretbox.Keys {
				typName := "XSalsa20-POLY1305 " + sbKey.Name
				if active {
					active = false
					state.ActiveKey = typName
				} else {
					state.InactiveKeys = append(state.InactiveKeys, typName)
				}
			}
		}
		if p.Identity != nil {
			active = false
		}
	}

	return state, nil
}

func encryptionEnable(ctx context.Context, server *config.Control, keyType string, enable bool) error {
	providers, err := secretsencrypt.GetEncryptionProviders(server.Runtime)
	if err != nil {
		return err
	}
	if len(providers) > 3 {
		return fmt.Errorf("more than 3 providers (%d) found in secrets encryption", len(providers))
	}
	curKeys, _, err := secretsencrypt.GetEncryptionKeys(server.Runtime)
	if err != nil {
		return err
	}

	if providers[1].Identity != nil && (providers[0].AESCBC != nil || providers[0].Secretbox != nil) && !enable {
		logrus.Infoln("Disabling secrets encryption")
		if err := secretsencrypt.WriteEncryptionConfig(server.Runtime, curKeys, []apiserverconfigv1.Key{}, keyType, enable); err != nil {
			return err
		}
	} else if !enable {
		logrus.Infoln("Secrets encryption already disabled")
		return nil
	} else if providers[0].Identity != nil && (providers[1].AESCBC != nil || providers[1].Secretbox != nil) && enable {
		logrus.Infoln("Enabling secrets encryption")
		if err := secretsencrypt.WriteEncryptionConfig(server.Runtime, curKeys, []apiserverconfigv1.Key{}, keyType, enable); err != nil {
			return err
		}
	} else if enable {
		logrus.Infoln("Secrets encryption already enabled")
		return nil
	} else {
		return fmt.Errorf("unable to enable/disable secrets encryption, unknown configuration")
	}
	return cluster.Save(ctx, server, true)
}

func encryptionConfigHandler(ctx context.Context, server *config.Control) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		if req.TLS == nil {
			resp.WriteHeader(http.StatusNotFound)
			return
		}
		if req.Method != http.MethodPut {
			resp.WriteHeader(http.StatusBadRequest)
			return
		}
		encryptReq, err := getEncryptionRequest(req)
		if err != nil {
			resp.WriteHeader(http.StatusBadRequest)
			resp.Write([]byte(err.Error()))
			return
		}
		if encryptReq.Stage != nil {
			switch *encryptReq.Stage {
			case secretsencrypt.EncryptionPrepare:
				err = encryptionPrepare(ctx, server, *encryptReq.KeyType, encryptReq.Force)
			case secretsencrypt.EncryptionRotate:
				err = encryptionRotate(ctx, server, encryptReq.Force)
			case secretsencrypt.EncryptionReencryptActive:
				err = encryptionReencrypt(ctx, server, encryptReq.Force, encryptReq.Skip, *encryptReq.KeyType)
			default:
				err = fmt.Errorf("unknown stage %s requested", *encryptReq.Stage)
			}
		} else if encryptReq.Enable != nil {
			err = encryptionEnable(ctx, server, *encryptReq.KeyType, *encryptReq.Enable)
		}

		if err != nil {
			genErrorMessage(resp, http.StatusBadRequest, err, "secrets-encrypt")
			return
		}
		// If a user kills the k3s server immediately after this call, we run into issues where the files
		// have not yet been written. This sleep ensures that things have time to sync to disk before
		// the request completes.
		time.Sleep(1 * time.Second)
		resp.WriteHeader(http.StatusOK)
	})
}

func encryptionPrepare(ctx context.Context, server *config.Control, keyType string, force bool) error {
	states := secretsencrypt.EncryptionStart + "-" + secretsencrypt.EncryptionReencryptFinished
	if err := verifyEncryptionHashAnnotation(server.Runtime, server.Runtime.Core.Core(), states); err != nil && !force {
		return err
	}

	curAESCBCKeys, curSBKeys, err := secretsencrypt.GetEncryptionKeys(server.Runtime)
	if err != nil {
		return err
	}
	newKey, err := GenNewEncryptionKey(keyType)
	if err != nil {
		return err
	}
	if keyType == secretsencrypt.AESCBCKeyType {
		curAESCBCKeys = append(curAESCBCKeys, newKey)
	} else if keyType == secretsencrypt.SecretBoxKeyType {
		curSBKeys = append(curSBKeys, newKey)
	}
	logrus.Infoln("Adding secrets-encryption key: ", newKey)

	if err := secretsencrypt.WriteEncryptionConfig(server.Runtime, curAESCBCKeys, curSBKeys, keyType, true); err != nil {
		return err
	}
	nodeName := os.Getenv("NODE_NAME")
	node, err := server.Runtime.Core.Core().V1().Node().Get(nodeName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if err = secretsencrypt.WriteEncryptionHashAnnotation(server.Runtime, node, secretsencrypt.EncryptionPrepare); err != nil {
		return err
	}
	return cluster.Save(ctx, server, true)
}

func encryptionRotate(ctx context.Context, server *config.Control, force bool) error {

	if err := verifyEncryptionHashAnnotation(server.Runtime, server.Runtime.Core.Core(), secretsencrypt.EncryptionPrepare); err != nil && !force {
		return err
	}

	curKeys, _, err := secretsencrypt.GetEncryptionKeys(server.Runtime)
	if err != nil {
		return err
	}

	// Right rotate elements
	rotatedKeys := append(curKeys[len(curKeys)-1:], curKeys[:len(curKeys)-1]...)

	if err = secretsencrypt.WriteEncryptionConfig(server.Runtime, rotatedKeys, []apiserverconfigv1.Key{}, secretsencrypt.AESCBCKeyType, true); err != nil {
		return err
	}
	logrus.Infoln("Encryption keys right rotated")
	nodeName := os.Getenv("NODE_NAME")
	node, err := server.Runtime.Core.Core().V1().Node().Get(nodeName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if err := secretsencrypt.WriteEncryptionHashAnnotation(server.Runtime, node, secretsencrypt.EncryptionRotate); err != nil {
		return err
	}
	return cluster.Save(ctx, server, true)
}

func encryptionReencrypt(ctx context.Context, server *config.Control, force bool, skip bool, keyType string) error {

	if err := verifyEncryptionHashAnnotation(server.Runtime, server.Runtime.Core.Core(), secretsencrypt.EncryptionRotate); err != nil && !force {
		return err
	}
	server.EncryptForce = force
	server.EncryptSkip = skip
	nodeName := os.Getenv("NODE_NAME")
	node, err := server.Runtime.Core.Core().V1().Node().Get(nodeName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	reencryptHash, err := secretsencrypt.GenReencryptHash(server.Runtime, secretsencrypt.EncryptionReencryptRequest)
	if err != nil {
		return err
	}
	ann := secretsencrypt.EncryptionReencryptRequest + "-" + reencryptHash
	node.Annotations[secretsencrypt.EncryptionHashAnnotation] = ann
	if _, err = server.Runtime.Core.Core().V1().Node().Update(node); err != nil {
		return err
	}
	logrus.Debugf("encryption hash annotation set successfully on node: %s\n", node.ObjectMeta.Name)
	return nil
}

func GenNewEncryptionKey(keyType string) (apiserverconfigv1.Key, error) {
	var keyByte []byte
	var keyPrefix string
	switch {
	case keyType == "secretbox":
		keyByte = make([]byte, secretBoxKeySize)
		keyPrefix = "secretboxkey-"
	case keyType == "aescbc":
		keyByte = make([]byte, aescbcKeySize)
		keyPrefix = "aescbckey-"
	}
	_, err := rand.Read(keyByte)
	if err != nil {
		return apiserverconfigv1.Key{}, err
	}
	encodedKey := base64.StdEncoding.EncodeToString(keyByte)

	newKey := apiserverconfigv1.Key{
		Name:   keyPrefix + time.Now().Format(time.RFC3339),
		Secret: encodedKey,
	}
	return newKey, nil
}

func getEncryptionHashAnnotation(core core.Interface) (string, string, error) {
	nodeName := os.Getenv("NODE_NAME")
	node, err := core.V1().Node().Get(nodeName, metav1.GetOptions{})
	if err != nil {
		return "", "", err
	}
	if _, ok := node.Labels[ControlPlaneRoleLabelKey]; !ok {
		return "", "", fmt.Errorf("cannot manage secrets encryption on non control-plane node %s", nodeName)
	}
	if ann, ok := node.Annotations[secretsencrypt.EncryptionHashAnnotation]; ok {
		split := strings.Split(ann, "-")
		if len(split) != 2 {
			return "", "", fmt.Errorf("invalid annotation %s found on node %s", ann, nodeName)
		}
		return split[0], split[1], nil
	}
	return "", "", fmt.Errorf("missing annotation on node %s", nodeName)
}

// verifyEncryptionHashAnnotation checks that all nodes are on the same stage,
// and that a request for new stage is valid
func verifyEncryptionHashAnnotation(runtime *config.ControlRuntime, core core.Interface, prevStage string) error {
	var firstHash string
	var firstNodeName string
	first := true
	labelSelector := labels.Set{ControlPlaneRoleLabelKey: "true"}.String()
	nodes, err := core.V1().Node().List(metav1.ListOptions{LabelSelector: labelSelector})
	if err != nil {
		return err
	}
	for _, node := range nodes.Items {
		hash, ok := node.Annotations[secretsencrypt.EncryptionHashAnnotation]
		if ok && first {
			firstHash = hash
			first = false
			firstNodeName = node.ObjectMeta.Name
		} else if ok && hash != firstHash {
			return fmt.Errorf("hash does not match between %s and %s", firstNodeName, node.ObjectMeta.Name)
		}
	}

	if prevStage == "" {
		return nil
	}

	oldStage, oldHash, err := getEncryptionHashAnnotation(core)
	if err != nil {
		return err
	}

	encryptionConfigHash, err := secretsencrypt.GenEncryptionConfigHash(runtime)
	if err != nil {
		return err
	}
	if !strings.Contains(prevStage, oldStage) {
		return fmt.Errorf("incorrect stage: %s found on node %s", oldStage, nodes.Items[0].ObjectMeta.Name)
	} else if oldHash != encryptionConfigHash {
		return fmt.Errorf("invalid hash: %s found on node %s", oldHash, nodes.Items[0].ObjectMeta.Name)
	}

	return nil
}

// genErrorMessage sends and logs a random error ID so that logs can be correlated
// between the REST API (which does not provide any detailed error output, to avoid
// information disclosure) and the server logs.
func genErrorMessage(resp http.ResponseWriter, statusCode int, passedErr error, component string) {
	errID, err := rand.Int(rand.Reader, big.NewInt(99999))
	if err != nil {
		resp.WriteHeader(http.StatusInternalServerError)
		resp.Write([]byte(err.Error()))
		return
	}
	logrus.Warnf("%s error ID %05d: %s", component, errID, passedErr.Error())
	resp.WriteHeader(statusCode)
	resp.Write([]byte(fmt.Sprintf("%s error ID %05d", component, errID)))
}
