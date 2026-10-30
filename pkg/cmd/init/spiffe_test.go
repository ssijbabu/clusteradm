// Copyright Contributors to the Open Cluster Management project
package init

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"

	operatorv1 "open-cluster-management.io/api/operator/v1"
	"open-cluster-management.io/clusteradm/pkg/config"
	genericclioptionsclusteradm "open-cluster-management.io/clusteradm/pkg/genericclioptions"
)

func TestSPIFFEValidate(t *testing.T) {
	ok := spiffeOptions{grpcIdentity: "spiffe", trustDomain: "hub1.example.org", signerType: "AzureKeyVault",
		azureVaultURL: "https://v.vault.azure.net", azureCertificateName: "ocm-spiffe-ca"}
	if err := ok.validate([]string{"grpc"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for name, c := range map[string]struct {
		mutate  func(*spiffeOptions)
		drivers []string
	}{
		"no grpc driver":     {mutate: func(*spiffeOptions) {}, drivers: []string{"csr"}},
		"unknown identity":   {mutate: func(s *spiffeOptions) { s.grpcIdentity = "x509" }, drivers: []string{"grpc"}},
		"no trust domain":    {mutate: func(s *spiffeOptions) { s.trustDomain = "" }, drivers: []string{"grpc"}},
		"unknown signer":     {mutate: func(s *spiffeOptions) { s.signerType = "Memory" }, drivers: []string{"grpc"}},
		"azure missing cert": {mutate: func(s *spiffeOptions) { s.azureCertificateName = "" }, drivers: []string{"grpc"}},
		"openbao incomplete": {mutate: func(s *spiffeOptions) { s.signerType = "OpenBao" }, drivers: []string{"grpc"}},
	} {
		s := ok
		c.mutate(&s)
		if err := s.validate(c.drivers); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if err := (&spiffeOptions{}).validate(nil); err != nil {
		t.Errorf("SPIFFE disabled must validate: %v", err)
	}
}

func TestSPIFFEHubConfig(t *testing.T) {
	o := &Options{registrationDrivers: []string{"grpc"}, spiffe: spiffeOptions{
		grpcIdentity: "spiffe", trustDomain: "hub1.example.org", signerType: "OpenBao",
		openBaoAddress: "https://bao:8200", openBaoKeyName: "k", openBaoCertificatePath: "secret/data/ca", openBaoAuthRole: "r",
		podLabels: map[string]string{"a": "b"},
	}}
	drivers, err := getRegistrationDrivers(o)
	if err != nil {
		t.Fatal(err)
	}
	cfg := drivers[0].GRPC.SPIFFE
	if cfg == nil || cfg.TokenAudience != "open-cluster-management.io/hub1.example.org" ||
		cfg.Signer.Type != operatorv1.SPIFFESignerTypeOpenBao || cfg.Signer.OpenBao.KeyName != "k" || cfg.PodLabels["a"] != "b" {
		t.Fatalf("unexpected SPIFFE config %+v", cfg)
	}
	cmd := o.spiffeJoinCommand("hub.example.org:443")
	for _, want := range []string{"--spiffe-grpc-server hub.example.org:443", "--spiffe-trust-domain hub1.example.org", "--spiffe-ca-fingerprint"} {
		if !strings.Contains(cmd, want) {
			t.Errorf("join command %q lacks %s", cmd, want)
		}
	}
	if strings.Contains(cmd, "--hub-token") {
		t.Error("the SPIFFE join command must not carry a token")
	}
}

func TestSPIFFEGRPCServer(t *testing.T) {
	lbService := func(ingress corev1.LoadBalancerIngress) *corev1.Service {
		return &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: config.ClusterManagerName + "-grpc-server", Namespace: config.HubClusterNamespace},
			Status:     corev1.ServiceStatus{LoadBalancer: corev1.LoadBalancerStatus{Ingress: []corev1.LoadBalancerIngress{ingress}}},
		}
	}
	cases := []struct {
		name         string
		grpcServer   string
		endpointType string
		dryRun       bool
		service      *corev1.Service
		want         string
	}{
		{name: "flag with port", grpcServer: "hub.example.org:8443", endpointType: "loadBalancer", want: "hub.example.org:8443"},
		{name: "flag without port", grpcServer: "hub.example.org", endpointType: "loadBalancer", want: "hub.example.org:443"},
		{name: "hostname endpoint", grpcServer: "hub.example.org:8090", endpointType: "hostname", want: "hub.example.org:8090"},
		{name: "load balancer IP", endpointType: "loadBalancer", service: lbService(corev1.LoadBalancerIngress{IP: "52.0.0.1"}), want: "52.0.0.1:443"},
		{name: "load balancer host name", endpointType: "loadBalancer",
			service: lbService(corev1.LoadBalancerIngress{Hostname: "lb.example.com"}), want: "lb.example.com:443"},
		{name: "no address assigned", endpointType: "loadBalancer", service: lbService(corev1.LoadBalancerIngress{}), want: grpcServerPlaceholder},
		{name: "dry run", endpointType: "loadBalancer", dryRun: true,
			service: lbService(corev1.LoadBalancerIngress{IP: "52.0.0.1"}), want: grpcServerPlaceholder},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client := kubefake.NewSimpleClientset()
			if c.service != nil {
				client = kubefake.NewSimpleClientset(c.service)
			}
			o := &Options{grpcServer: c.grpcServer, grpcEndpointType: c.endpointType,
				ClusteradmFlags: &genericclioptionsclusteradm.ClusteradmFlags{DryRun: c.dryRun, Timeout: 1}}
			if got := o.spiffeGRPCServer(context.Background(), client); got != c.want {
				t.Errorf("want %q, got %q", c.want, got)
			}
		})
	}
}
