// Copyright Contributors to the Open Cluster Management project
package init

import (
	"strings"
	"testing"

	operatorv1 "open-cluster-management.io/api/operator/v1"
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
	o.grpcServer = "hub.example.org:443"
	cmd := o.spiffeJoinCommand()
	for _, want := range []string{"--spiffe-grpc-server hub.example.org:443", "--spiffe-trust-domain hub1.example.org", "--spiffe-ca-fingerprint"} {
		if !strings.Contains(cmd, want) {
			t.Errorf("join command %q lacks %s", cmd, want)
		}
	}
	if strings.Contains(cmd, "--hub-token") {
		t.Error("the SPIFFE join command must not carry a token")
	}
}
