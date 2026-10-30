// Copyright Contributors to the Open Cluster Management project
package accept

import (
	"context"
	"fmt"
	"os"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	clusterclientset "open-cluster-management.io/api/client/cluster/clientset/versioned"
	clusterv1 "open-cluster-management.io/api/cluster/v1"
	spiffehelpers "open-cluster-management.io/clusteradm/pkg/helpers/spiffe"
)

// acceptSPIFFE accepts a cluster that joined with SPIFFE identities: it binds
// the cluster's token issuer and agent ServiceAccounts in an admin-only
// ManagedClusterIdentity and creates the accepted ManagedCluster. There is no
// CSR to approve; the agents get their SVIDs once the binding exists.
func (o *Options) acceptSPIFFE(ctx context.Context, clusterClient clusterclientset.Interface) error {
	data, err := os.ReadFile(o.IdentityFile)
	if err != nil {
		return fmt.Errorf("--identity-file %q read failed: %w", o.IdentityFile, err)
	}
	mcid, err := spiffehelpers.UnmarshalIdentityFile(data, o.IdentityThumbprints)
	if err != nil {
		return err
	}
	if len(o.Values.Clusters) != 1 || o.Values.Clusters[0] != mcid.Name {
		return fmt.Errorf("--identity-file is for cluster %q; pass exactly --clusters %s", mcid.Name, mcid.Name)
	}
	if o.ClusteradmFlags.DryRun {
		return nil
	}

	identities := clusterClient.ClusterV1alpha1().ManagedClusterIdentities()
	existing, err := identities.Get(ctx, mcid.Name, metav1.GetOptions{})
	switch {
	case errors.IsNotFound(err):
		if _, err := identities.Create(ctx, mcid, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("failed to create ManagedClusterIdentity %s: %w", mcid.Name, err)
		}
	case err != nil:
		return err
	default:
		updated := existing.DeepCopy()
		updated.Spec = mcid.Spec
		if _, err := identities.Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("failed to update ManagedClusterIdentity %s: %w", mcid.Name, err)
		}
	}
	fmt.Fprintf(o.Streams.Out, "Bound the token issuer and agent ServiceAccounts of cluster %s\n", mcid.Name)

	clusters := clusterClient.ClusterV1().ManagedClusters()
	mc, err := clusters.Get(ctx, mcid.Name, metav1.GetOptions{})
	switch {
	case errors.IsNotFound(err):
		_, err = clusters.Create(ctx, &clusterv1.ManagedCluster{
			ObjectMeta: metav1.ObjectMeta{Name: mcid.Name},
			Spec:       clusterv1.ManagedClusterSpec{HubAcceptsClient: true},
		}, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create ManagedCluster %s: %w", mcid.Name, err)
		}
	case err != nil:
		return err
	case !mc.Spec.HubAcceptsClient:
		updated := mc.DeepCopy()
		updated.Spec.HubAcceptsClient = true
		if _, err := clusters.Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
			return err
		}
	}
	fmt.Fprintf(o.Streams.Out, "Accepted managed cluster %s. Its agents obtain their SVIDs on their next retry.\n", mcid.Name)
	return nil
}
