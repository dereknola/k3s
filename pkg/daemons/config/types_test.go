package config

import (
	"reflect"
	"testing"
)

func Test_UnitGetArgs(t *testing.T) {
	type args struct {
		argsMap   map[string]string
		extraArgs []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "Default Test",
			args: args{
				argsMap: map[string]string{
					"aaa": "A",
					"bbb": "B",
					"ccc": "C",
					"ddd": "d",
					"eee": "e",
					"fff": "f",
					"ggg": "g",
					"hhh": "h",
				},
				extraArgs: []string{
					"bbb=BB",
					"ddd=DD",
					"iii=II",
				},
			},

			want: []string{
				"--aaa=A",
				"--bbb=BB",
				"--ccc=C",
				"--ddd=DD",
				"--eee=e",
				"--fff=f",
				"--ggg=g",
				"--hhh=h",
				"--iii=II",
			},
		},
		{
			name: "Args with existing hyphens Test",
			args: args{
				argsMap: map[string]string{
					"aaa": "A",
					"bbb": "B",
					"ccc": "C",
					"ddd": "d",
					"eee": "e",
					"fff": "f",
					"ggg": "g",
					"hhh": "h",
				},
				extraArgs: []string{
					"--bbb=BB",
					"--ddd=DD",
					"--iii=II",
				},
			},

			want: []string{
				"--aaa=A",
				"--bbb=BB",
				"--ccc=C",
				"--ddd=DD",
				"--eee=e",
				"--fff=f",
				"--ggg=g",
				"--hhh=h",
				"--iii=II",
			},
		},
		{
			name: "Multiple args with defaults Test",
			args: args{
				argsMap: map[string]string{
					"aaa": "A",
					"bbb": "B",
				},
				extraArgs: []string{
					"--ccc=C",
					"--bbb=DD",
					"--bbb=AA",
				},
			},

			want: []string{
				"--aaa=A",
				"--bbb=DD",
				"--bbb=AA",
				"--ccc=C",
			},
		},
		{
			name: "Multiple args with defaults and prefix",
			args: args{
				argsMap: map[string]string{
					"aaa": "A",
					"bbb": "B",
				},
				extraArgs: []string{
					"--ccc=C",
					"--bbb-=DD",
				},
			},

			want: []string{
				"--aaa=A",
				"--bbb=DD",
				"--bbb=B",
				"--ccc=C",
			},
		},
		{
			name: "Multiple args with defaults and suffix",
			args: args{
				argsMap: map[string]string{
					"aaa": "A",
					"bbb": "B",
				},
				extraArgs: []string{
					"--ccc=C",
					"--bbb+=DD",
				},
			},

			want: []string{
				"--aaa=A",
				"--bbb=B",
				"--bbb=DD",
				"--ccc=C",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetArgs(tt.args.argsMap, tt.args.extraArgs); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetArgs() = %+v\nWant = %+v", got, tt.want)
			}
		})
	}
}

func Test_UnitGetYaml(t *testing.T) {
	var defaultArgs = map[string]string{
		"address":                      "0.0.0.0",
		"allowed-unsafe-sysctls":       "net.ipv4.ip_forward,net.ipv6.conf.all.forwarding",
		"anonymous-auth":               "false",
		"authentication-token-webhook": "true",
		"authorization-mode":           "Webhook",
		"cgroup-driver":                "cgroupfs",
		"client-ca-file":               "/var/lib/rancher/k3s/agent/client-ca.crt",
		"cloud-provider":               "external",
		"cluster-dns":                  "10.43.0.10",
		"cluster-domain":               "cluster.local",
		"container-runtime-endpoint":   "unix:///run/k3s/containerd/containerd.sock",
		"containerd":                   "/run/k3s/containerd/containerd.sock",
		"eviction-hard":                "imagefs.available\u003c5%,nodefs.available\u003c5%",
		"eviction-minimum-reclaim":     "imagefs.available=10%,nodefs.available=10%",
		"fail-swap-on":                 "false",
		"healthz-bind-address":         "127.0.0.1",
	}
	var defaultYaml = `address: 0.0.0.0
allowed-unsafe-sysctls: net.ipv4.ip_forward,net.ipv6.conf.all.forwarding
anonymous-auth: "false"
authentication-token-webhook: "true"
authorization-mode: Webhook
cgroup-driver: cgroupfs
client-ca-file: /var/lib/rancher/k3s/agent/client-ca.crt
cloud-provider: external
cluster-dns: 10.43.0.10
cluster-domain: cluster.local
container-runtime-endpoint: unix:///run/k3s/containerd/containerd.sock
containerd: /run/k3s/containerd/containerd.sock
eviction-hard: imagefs.available<5%,nodefs.available<5%
eviction-minimum-reclaim: imagefs.available=10%,nodefs.available=10%
fail-swap-on: "false"
healthz-bind-address: 127.0.0.1
`

	type args struct {
		initialArgs map[string]string
		extraArgs   []string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Default Kublet args",
			args: args{
				initialArgs: defaultArgs,
				extraArgs:   []string{},
			},

			want: defaultYaml,
		},
		{
			name: "Kublet with extra args",
			args: args{
				initialArgs: defaultArgs,
				extraArgs: []string{
					"--hostname-override=hostname01",
					"--make-iptables-util-chains=true",
				},
			},

			want: defaultYaml + "hostname-override: hostname01\n" + "make-iptables-util-chains: \"true\"\n",
		},
		{
			name: "Kublet with repeated extra args",
			args: args{
				initialArgs: defaultArgs,
				extraArgs: []string{
					"--tls-cipher-suites='TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'",
				},
			},

			want: defaultYaml,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetYaml(tt.args.initialArgs, tt.args.extraArgs); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetYaml() = %+v\nWant = %+v", got, tt.want)
			}
		})
	}
}
