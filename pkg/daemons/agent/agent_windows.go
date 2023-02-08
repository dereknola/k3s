//go:build windows
// +build windows

package agent

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/k3s-io/k3s/pkg/daemons/config"
	"github.com/k3s-io/k3s/pkg/util"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/net"
	"k8s.io/kubelet/config/v1beta1"

	"k8s.io/kubernetes/pkg/kubeapiserver/authorizer/modes"
	"k8s.io/utils/pointer"
)

const (
	socketPrefix = "npipe://"
)

func kubeProxyArgs(cfg *config.Agent) map[string]string {
	bindAddress := "127.0.0.1"
	_, IPv6only, _ := util.GetFirstString([]string{cfg.NodeIP})
	if IPv6only {
		bindAddress = "::1"
	}
	argsMap := map[string]string{
		"proxy-mode":           "kernelspace",
		"healthz-bind-address": bindAddress,
		"kubeconfig":           cfg.KubeConfigKubeProxy,
		"cluster-cidr":         util.JoinIPNets(cfg.ClusterCIDRs),
	}
	if cfg.NodeName != "" {
		argsMap["hostname-override"] = cfg.NodeName
	}

	return argsMap
}

func kubeletCLIArgs(cfg *config.Agent) map[string]string {
	bindAddress := "127.0.0.1"
	_, IPv6only, _ := util.GetFirstString([]string{cfg.NodeIP})
	if IPv6only {
		bindAddress = "::1"
	}
	argsMap := map[string]string{
		"healthz-bind-address":         bindAddress,
		"read-only-port":               "0",
		"cluster-domain":               cfg.ClusterDomain,
		"kubeconfig":                   cfg.KubeConfigKubelet,
		"eviction-hard":                "imagefs.available<5%,nodefs.available<5%",
		"eviction-minimum-reclaim":     "imagefs.available=10%,nodefs.available=10%",
		"fail-swap-on":                 "false",
		"authentication-token-webhook": "true",
		"anonymous-auth":               "false",
		"authorization-mode":           modes.ModeWebhook,
	}
	if cfg.PodManifests != "" && argsMap["pod-manifest-path"] == "" {
		argsMap["pod-manifest-path"] = cfg.PodManifests
	}
	if err := os.MkdirAll(argsMap["pod-manifest-path"], 0755); err != nil {
		logrus.Errorf("Failed to mkdir %s: %v", argsMap["pod-manifest-path"], err)
	}
	if cfg.RootDir != "" {
		argsMap["root-dir"] = cfg.RootDir
		argsMap["cert-dir"] = filepath.Join(cfg.RootDir, "pki")
	}
	if len(cfg.ClusterDNS) > 0 {
		argsMap["cluster-dns"] = util.JoinIPs(cfg.ClusterDNSs)
	}
	if cfg.ResolvConf != "" {
		argsMap["resolv-conf"] = cfg.ResolvConf
	}
	if cfg.RuntimeSocket != "" {
		argsMap["serialize-image-pulls"] = "false"
		// cadvisor wants the containerd CRI socket without the prefix, but kubelet wants it with the prefix
		if strings.HasPrefix(cfg.RuntimeSocket, socketPrefix) {
			argsMap["container-runtime-endpoint"] = cfg.RuntimeSocket
		} else {
			argsMap["container-runtime-endpoint"] = socketPrefix + cfg.RuntimeSocket
		}
	}
	if cfg.PauseImage != "" {
		argsMap["pod-infra-container-image"] = cfg.PauseImage
	}
	if cfg.ListenAddress != "" {
		argsMap["address"] = cfg.ListenAddress
	}
	if cfg.ClientCA != "" {
		argsMap["anonymous-auth"] = "false"
		argsMap["client-ca-file"] = cfg.ClientCA
	}
	if cfg.ServingKubeletCert != "" && cfg.ServingKubeletKey != "" {
		argsMap["tls-cert-file"] = cfg.ServingKubeletCert
		argsMap["tls-private-key-file"] = cfg.ServingKubeletKey
	}
	if cfg.NodeName != "" {
		argsMap["hostname-override"] = cfg.NodeName
	}
	defaultIP, err := net.ChooseHostInterface()
	if err != nil || defaultIP.String() != cfg.NodeIP {
		argsMap["node-ip"] = cfg.NodeIP
	}

	argsMap["node-labels"] = strings.Join(cfg.NodeLabels, ",")
	if len(cfg.NodeTaints) > 0 {
		argsMap["register-with-taints"] = strings.Join(cfg.NodeTaints, ",")
	}

	if !cfg.DisableCCM {
		argsMap["cloud-provider"] = "external"
	}

	if ImageCredProvAvailable(cfg) {
		logrus.Infof("Kubelet image credential provider bin dir and configuration file found.")
		argsMap["feature-gates"] = util.AddFeatureGate(argsMap["feature-gates"], "KubeletCredentialProviders=true")
		argsMap["image-credential-provider-bin-dir"] = cfg.ImageCredProvBinDir
		argsMap["image-credential-provider-config"] = cfg.ImageCredProvConfig
	}

	if cfg.ProtectKernelDefaults {
		argsMap["protect-kernel-defaults"] = "true"
	}
	return argsMap
}

// kubeletConfig returns a maximal kubelet configuration for writing to a file, and a
// minimal argument map for passing to the kubelet CLI, as some values are exclusive to CLI and some to config file.
func kubeletConfig(cfg *config.Agent) (v1beta1.KubeletConfiguration, map[string]string) {
	bindAddress := "127.0.0.1"
	_, IPv6only, _ := util.GetFirstString([]string{cfg.NodeIP})
	if IPv6only {
		bindAddress = "::1"
	}
	argsMap := map[string]string{
		"kubeconfig": cfg.KubeConfigKubelet,
	}
	kubeletConfig := v1beta1.KubeletConfiguration{
		TypeMeta: metav1.TypeMeta{
			Kind:       "KubeletConfiguration",
			APIVersion: "kubelet.config.k8s.io/v1beta1",
		},
		HealthzBindAddress: bindAddress,
		ReadOnlyPort:       0,
		ClusterDomain:      cfg.ClusterDomain,
		EvictionHard: map[string]string{
			"imagefs.available": "5%",
			"nodefs.available":  "5%",
		},
		EvictionMinimumReclaim: map[string]string{
			"imagefs.available": "10%",
			"nodefs.available":  "10%",
		},
		FailSwapOn: pointer.Bool(false),
		Authentication: v1beta1.KubeletAuthentication{
			Webhook: v1beta1.KubeletWebhookAuthentication{
				Enabled: pointer.Bool(true),
			},
		},
		Authorization: v1beta1.KubeletAuthorization{
			Mode: v1beta1.KubeletAuthorizationModeWebhook,
		},
	}
	if cfg.PodManifests != "" && argsMap["pod-manifest-path"] == "" {
		argsMap["pod-manifest-path"] = cfg.PodManifests
	}
	if err := os.MkdirAll(argsMap["pod-manifest-path"], 0755); err != nil {
		logrus.Errorf("Failed to mkdir %s: %v", argsMap["pod-manifest-path"], err)
	}
	if cfg.RootDir != "" {
		argsMap["root-dir"] = cfg.RootDir
		argsMap["cert-dir"] = filepath.Join(cfg.RootDir, "pki")
	}
	if len(cfg.ClusterDNS) > 0 {
		kubeletConfig.ClusterDNS = util.JoinIPsSlice(cfg.ClusterDNSs)
	}
	if cfg.ResolvConf != "" {
		kubeletConfig.ResolverConfig = pointer.String(cfg.ResolvConf)
	}
	if cfg.RuntimeSocket != "" {
		kubeletConfig.SerializeImagePulls = pointer.Bool(false)
		// cadvisor wants the containerd CRI socket without the prefix, but kubelet wants it with the prefix
		if strings.HasPrefix(cfg.RuntimeSocket, socketPrefix) {
			argsMap["container-runtime-endpoint"] = cfg.RuntimeSocket
		} else {
			argsMap["container-runtime-endpoint"] = socketPrefix + cfg.RuntimeSocket
		}
	}
	if cfg.PauseImage != "" {
		argsMap["pod-infra-container-image"] = cfg.PauseImage
	}
	if cfg.ListenAddress != "" {
		kubeletConfig.Address = cfg.ListenAddress
	}
	if cfg.ClientCA != "" {
		kubeletConfig.Authentication.Anonymous.Enabled = pointer.Bool(false)
		kubeletConfig.Authentication.X509.ClientCAFile = cfg.ClientCA
	}
	if cfg.ServingKubeletCert != "" && cfg.ServingKubeletKey != "" {
		kubeletConfig.TLSCertFile = cfg.ServingKubeletCert
		kubeletConfig.TLSPrivateKeyFile = cfg.ServingKubeletKey
	}
	if cfg.NodeName != "" {
		argsMap["hostname-override"] = cfg.NodeName
	}
	defaultIP, err := net.ChooseHostInterface()
	if err != nil || defaultIP.String() != cfg.NodeIP {
		argsMap["node-ip"] = cfg.NodeIP
	}

	argsMap["node-labels"] = strings.Join(cfg.NodeLabels, ",")
	if len(cfg.NodeTaints) > 0 {
		argsMap["register-with-taints"] = strings.Join(cfg.NodeTaints, ",")
	}

	if !cfg.DisableCCM {
		argsMap["cloud-provider"] = "external"
	}

	if ImageCredProvAvailable(cfg) {
		logrus.Infof("Kubelet image credential provider bin dir and configuration file found.")
		argsMap["feature-gates"] = util.AddFeatureGate(argsMap["feature-gates"], "KubeletCredentialProviders=true")
		argsMap["image-credential-provider-bin-dir"] = cfg.ImageCredProvBinDir
		argsMap["image-credential-provider-config"] = cfg.ImageCredProvConfig
	}

	if cfg.ProtectKernelDefaults {
		kubeletConfig.ProtectKernelDefaults = true
	}

	return kubeletConfig, argsMap
}
