// Copyright Contributors to the Open Cluster Management project
package accept

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericiooptions"

	clusterfake "open-cluster-management.io/api/client/cluster/clientset/versioned/fake"
	clusterv1alpha1 "open-cluster-management.io/api/cluster/v1alpha1"
	genericclioptionsclusteradm "open-cluster-management.io/clusteradm/pkg/genericclioptions"
	spiffehelpers "open-cluster-management.io/clusteradm/pkg/helpers/spiffe"
)

const jwks = `{"keys":[{"kty":"EC","kid":"k1","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}`

func writeIdentity(t *testing.T) (string, []string) {
	t.Helper()
	thumbprints, err := spiffehelpers.Thumbprints([]byte(jwks))
	if err != nil {
		t.Fatal(err)
	}
	data, err := spiffehelpers.MarshalIdentityFile(&clusterv1alpha1.ManagedClusterIdentity{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster1"},
		Spec: clusterv1alpha1.ManagedClusterIdentitySpec{
			Issuer: "https://spoke1.example.org",
			JWKS:   jwks,
			ServiceAccounts: []clusterv1alpha1.BoundServiceAccount{
				{Namespace: "open-cluster-management-agent", Name: "klusterlet-registration-sa", UID: "u1", Agent: "registration"},
			},
		},
	}, thumbprints)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "cluster1-identity.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, thumbprints
}

func newSPIFFEOptions(file string, thumbprints []string) *Options {
	return &Options{
		ClusteradmFlags:     genericclioptionsclusteradm.NewClusteradmFlags(nil),
		Values:              Values{Clusters: []string{"cluster1"}},
		IdentityFile:        file,
		IdentityThumbprints: thumbprints,
		Streams:             genericiooptions.IOStreams{Out: &bytes.Buffer{}, ErrOut: &bytes.Buffer{}},
	}
}

func TestAcceptSPIFFECreatesBindingAndAcceptedCluster(t *testing.T) {
	path, thumbprints := writeIdentity(t)
	client := clusterfake.NewSimpleClientset()
	if err := newSPIFFEOptions(path, thumbprints).acceptSPIFFE(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	mcid, err := client.ClusterV1alpha1().ManagedClusterIdentities().Get(context.Background(), "cluster1", metav1.GetOptions{})
	if err != nil || mcid.Spec.ServiceAccounts[0].UID != "u1" {
		t.Fatalf("ManagedClusterIdentity not created: %v", err)
	}
	mc, err := client.ClusterV1().ManagedClusters().Get(context.Background(), "cluster1", metav1.GetOptions{})
	if err != nil || !mc.Spec.HubAcceptsClient {
		t.Fatalf("ManagedCluster not created as accepted: %v", err)
	}
}

func TestAcceptSPIFFERefusesUnconfirmedKeys(t *testing.T) {
	path, _ := writeIdentity(t)
	client := clusterfake.NewSimpleClientset()
	if err := newSPIFFEOptions(path, []string{"wrong"}).acceptSPIFFE(context.Background(), client); err == nil {
		t.Fatal("expected unconfirmed issuer keys to be refused")
	}
	if _, err := client.ClusterV1alpha1().ManagedClusterIdentities().Get(context.Background(), "cluster1", metav1.GetOptions{}); err == nil {
		t.Fatal("nothing may be bound when the keys are not confirmed")
	}
}

func TestAcceptSPIFFERefusesOtherCluster(t *testing.T) {
	path, thumbprints := writeIdentity(t)
	o := newSPIFFEOptions(path, thumbprints)
	o.Values.Clusters = []string{"cluster2"}
	if err := o.acceptSPIFFE(context.Background(), clusterfake.NewSimpleClientset()); err == nil {
		t.Fatal("expected an identity file for another cluster to be refused")
	}
}
