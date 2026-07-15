package kata

import (
	"fmt"
	"os"
	"strings"
	"testing"

	testutil "github.com/k3s-io/k3s/tests/integration"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	kataManifestsDir = "/var/lib/rancher/k3s/server/manifests"
	kataShim         = "/opt/kata/bin/containerd-shim-kata-v2"
)

var (
	server   *testutil.K3sServer
	testLock int
)

var _ = BeforeSuite(func() {
	if testutil.IsExistingServer() {
		Skip("Test does not support running on existing k3s servers")
	}

	var err error
	testLock, err = testutil.K3sTestLock()
	Expect(err).NotTo(HaveOccurred())

	Expect(os.CopyFS(kataManifestsDir, os.DirFS("test-data"))).To(Succeed())

	server, err = testutil.K3sStartServer()
	Expect(err).NotTo(HaveOccurred())
})

var _ = Describe("Kata runtime", Ordered, func() {
	It("installs kata-deploy", func() {
		Eventually(func() error {
			if _, err := os.Stat(kataShim); err != nil {
				return fmt.Errorf("kata shim not installed: %w", err)
			}
			return nil
		}, "4m", "10s").Should(Succeed())
	})

	It("restarts K3s after Kata installation", func() {
		Expect(testutil.K3sKillServer(server)).To(Succeed())

		var err error
		server, err = testutil.K3sStartServer()
		Expect(err).NotTo(HaveOccurred())
	})

	It("finds the kata runtime", func() {
		Eventually(func() error {
			configToml, err := os.ReadFile("/var/lib/rancher/k3s/agent/etc/containerd/config.toml")
			if err != nil {
				return err
			}
			if !strings.Contains(string(configToml), "io.containerd.kata.v2") {
				return fmt.Errorf("generated containerd config does not contain kata runtime")
			}
			return nil
		}, "60s", "5s").Should(Succeed())
		Expect(testutil.SearchK3sLog(server, "Found kata container runtime")).To(BeTrue())
	})

	It("starts a Kata workload", func() {
		output, err := testutil.K3sCmd("kubectl apply -f ./qs.yaml")
		Expect(err).NotTo(HaveOccurred(), output)

		Eventually(func() error {
			pod, err := testutil.GetPod("default", "kata-quickstart")
			if err != nil {
				return err
			}
			if pod.Status.Phase != "Succeeded" {
				return fmt.Errorf("pod is %s: %s", pod.Status.Phase, pod.Status.Message)
			}
			return nil
		}, "5m", "5s").Should(Succeed())

		kataUname, err := testutil.K3sCmd("kubectl logs kata-quickstart")
		Expect(err).NotTo(HaveOccurred(), output)
		Expect(kataUname).NotTo(BeEmpty())

		hostUname, err := testutil.RunCommand("uname -r")
		Expect(err).NotTo(HaveOccurred())
		Expect(hostUname).NotTo(Equal(kataUname), "Kata workload is not running in a VM")
	})
})

var failed bool
var _ = AfterEach(func() {
	failed = failed || CurrentSpecReport().Failed()
})

var _ = AfterSuite(func() {
	if server != nil {
		if failed {
			testutil.K3sSaveLog(server, false)
			testutil.K3sCopyPodLogs(server)
			testutil.K3sDumpResources(server, "node", "pod")
		}
		Expect(testutil.K3sKillServer(server)).To(Succeed())
	}
	Expect(os.RemoveAll("/opt/kata")).To(Succeed())
	Expect(testutil.K3sCleanup(testLock, "")).To(Succeed())
})

func Test_IntegrationKata(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Kata Runtime Suite")
}
