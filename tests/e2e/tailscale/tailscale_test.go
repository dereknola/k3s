package tailscale

import (
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/k3s-io/k3s/tests"
	"github.com/k3s-io/k3s/tests/e2e"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Valid nodeOS: bento/ubuntu-24.04, opensuse/Leap-15.6.x86_64
var nodeOS = flag.String("nodeOS", "bento/ubuntu-24.04", "VM operating system")
var serverCount = flag.Int("serverCount", 1, "number of server nodes")
var agentCount = flag.Int("agentCount", 2, "number of agent nodes")
var ci = flag.Bool("ci", false, "running on CI")
var local = flag.Bool("local", false, "deploy a locally built K3s binary")

func Test_E2ETailscale(t *testing.T) {
	flag.Parse()
	RegisterFailHandler(Fail)
	suiteConfig, reporterConfig := GinkgoConfiguration()
	RunSpecs(t, "Tailscale Test Suite", suiteConfig, reporterConfig)
}

var tc *e2e.TestConfig

var _ = ReportAfterEach(e2e.GenReport)

var _ = Describe("Verify Tailscale Configuration", Ordered, func() {

	It("Starts up with no issues", func() {
		var err error
		if *local {
			tc, err = e2e.CreateLocalCluster(*nodeOS, *serverCount, *agentCount)
		} else {
			tc, err = e2e.CreateCluster(*nodeOS, *serverCount, *agentCount)
		}
		Expect(err).NotTo(HaveOccurred(), e2e.GetVagrantLog(err))
		By("CLUSTER CONFIG")
		By("OS: " + *nodeOS)
		By(tc.Status())
		Expect(err).NotTo(HaveOccurred())
	})

	// Server node needs to be ready before we continue
	It("Checks Server Status", func() {
		Eventually(func() error {
			return tests.NodesReady(tc.KubeconfigFile, e2e.VagrantSlice(tc.Servers))
		}, "360s", "5s").Should(Succeed())
		e2e.DumpNodes(tc.KubeconfigFile)
	})

	It("Change agent's config", func() {
		nodeIPs, _ := e2e.GetNodeIPs(tc.KubeconfigFile)
		cmd := fmt.Sprintf("sudo sed -i 's/TAILSCALEIP/%s/g' /etc/rancher/k3s/config.yaml", nodeIPs[0].IPv4)
		for _, agent := range tc.Agents {
			_, err := agent.RunCmdOnNode(cmd)
			Expect(err).NotTo(HaveOccurred())
		}
	})

	It("Restart agents", func() {
		err := e2e.RestartCluster(tc.Agents)
		Expect(err).NotTo(HaveOccurred(), e2e.GetVagrantLog(err))
	})

	It("Checks Node Status", func() {
		Eventually(func() error {
			return tests.NodesReady(tc.KubeconfigFile, e2e.VagrantSlice(tc.AllNodes()))
		}, "360s", "5s").Should(Succeed())
		e2e.DumpNodes(tc.KubeconfigFile)
	})

	It("Verifies that server and agent have a tailscale IP as nodeIP", func() {
		nodeIPs, err := e2e.GetNodeIPs(tc.KubeconfigFile)
		Expect(err).NotTo(HaveOccurred())
		for _, node := range nodeIPs {
			Expect(node.IPv4).Should(ContainSubstring("100."))
		}
	})

	It("Verify routing is correct and uses tailscale0 interface for internode traffic", func() {
		// table 52 is the one configured by tailscale
		cmd := "ip route show table 52"
		for _, node := range tc.AllNodes() {
			output, err := node.RunCmdOnNode(cmd)
			fmt.Println(err)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).Should(ContainSubstring("10.42."))
		}
	})

})

var failed bool
var _ = AfterEach(func() {
	failed = failed || CurrentSpecReport().Failed()
})

var _ = AfterSuite(func() {
	if failed {
		AddReportEntry("journald-logs", e2e.TailJournalLogs(1000, tc.AllNodes()))
	} else {
		Expect(e2e.GetCoverageReport(tc.AllNodes())).To(Succeed())
	}
	if !failed || *ci {
		Expect(e2e.DestroyCluster()).To(Succeed())
		Expect(os.Remove(tc.KubeconfigFile)).To(Succeed())
	}
})
