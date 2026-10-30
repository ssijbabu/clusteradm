// Copyright Contributors to the Open Cluster Management project
package join

import (
	"bytes"
	"context"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"k8s.io/cli-runtime/pkg/genericiooptions"

	operatorv1 "open-cluster-management.io/api/operator/v1"
	genericclioptionsclusteradm "open-cluster-management.io/clusteradm/pkg/genericclioptions"
	spiffehelpers "open-cluster-management.io/clusteradm/pkg/helpers/spiffe"
	"open-cluster-management.io/ocm/pkg/operator/helpers/chart"
	"open-cluster-management.io/ocm/pkg/server/spiffe/signer/memory"
)

func newSPIFFEJoin(t *testing.T, fingerprint string) *Options {
	t.Helper()
	_, ca, err := memory.NewSelfSignedCA("hub1.example.org", time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(t.TempDir(), "hub-ca.pem")
	if err := os.WriteFile(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if fingerprint == "" {
		fingerprint = spiffehelpers.Fingerprint(ca)
	}
	o := &Options{
		ClusteradmFlags:       genericclioptionsclusteradm.NewClusteradmFlags(nil),
		clusterName:           "cluster1",
		klusterletChartConfig: chart.NewDefaultKlusterletChartConfig(),
		Streams:               genericiooptions.IOStreams{Out: &bytes.Buffer{}, ErrOut: &bytes.Buffer{}},
		spiffe: spiffeOptions{
			trustDomain: "hub1.example.org", tokenAudience: "open-cluster-management.io/hub1",
			grpcServer: "hub.example.org:443", caBundleFile: bundle, caFingerprints: []string{fingerprint},
		},
	}
	o.klusterletChartConfig.Klusterlet.ClusterName = "cluster1"
	o.klusterletChartConfig.Klusterlet.Mode = operatorv1.InstallModeDefault
	if err := o.completeSPIFFE(); err != nil {
		t.Fatal(err)
	}
	return o
}

func TestSPIFFEJoinConfiguresKlusterlet(t *testing.T) {
	o := newSPIFFEJoin(t, "")
	if err := o.validateSPIFFE(context.Background()); err != nil {
		t.Fatalf("genuine hub CA refused: %v", err)
	}
	driver := o.klusterletChartConfig.Klusterlet.RegistrationConfiguration.RegistrationDriver
	if driver.AuthType != operatorv1.GRPCAuthType || driver.SPIFFE == nil || driver.SPIFFE.GRPCServerAddress != "hub.example.org:443" {
		t.Fatalf("klusterlet not configured for SPIFFE: %+v", driver)
	}
	if o.klusterletChartConfig.BootstrapHubKubeConfig != "" {
		t.Fatal("SPIFFE join must not create a bootstrap kubeconfig")
	}
	if o.spiffe.identityFile != "cluster1-identity.yaml" {
		t.Errorf("unexpected identity file %q", o.spiffe.identityFile)
	}
}

func TestSPIFFEJoinStopsOnFingerprintMismatch(t *testing.T) {
	o := newSPIFFEJoin(t, "sha256:"+string(bytes.Repeat([]byte("0"), 64)))
	if err := o.validateSPIFFE(context.Background()); err == nil {
		t.Fatal("a hub CA that does not match the out-of-band fingerprint must stop the join")
	}
}

func TestSPIFFEJoinRefusesHostedMode(t *testing.T) {
	o := newSPIFFEJoin(t, "")
	o.klusterletChartConfig.Klusterlet.Mode = operatorv1.InstallModeHosted
	if err := o.validateSPIFFE(context.Background()); err == nil {
		t.Fatal("SPIFFE join in Hosted mode must be refused")
	}
}
