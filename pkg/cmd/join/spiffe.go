// Copyright Contributors to the Open Cluster Management project
package join

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	clusterv1alpha1 "open-cluster-management.io/api/cluster/v1alpha1"
	operatorv1 "open-cluster-management.io/api/operator/v1"
	"open-cluster-management.io/clusteradm/pkg/cmd/join/preflight"
	"open-cluster-management.io/clusteradm/pkg/helpers"
	preflightinterface "open-cluster-management.io/clusteradm/pkg/helpers/preflight"
	"open-cluster-management.io/clusteradm/pkg/helpers/reader"
	spiffehelpers "open-cluster-management.io/clusteradm/pkg/helpers/spiffe"
	"open-cluster-management.io/ocm/pkg/server/spiffe/trustbundle"
)

// spiffeOptions configure joining a hub that uses SPIFFE identities. Only
// public data travels between the clusters: no hub token is used.
type spiffeOptions struct {
	trustDomain    string
	tokenAudience  string
	grpcServer     string
	caBundleFile   string
	caFingerprints []string
	identityFile   string
	pinIssuerKeys  bool

	caBundle []*x509.Certificate
}

func (s *spiffeOptions) addFlags(fs *pflag.FlagSet) {
	fs.StringVar(&s.trustDomain, "spiffe-trust-domain", "", "The hub's SPIFFE trust domain. Joins the hub with SPIFFE identities.")
	fs.StringVar(&s.tokenAudience, "spiffe-token-audience", "", "The hub's token audience.")
	fs.StringVar(&s.grpcServer, "spiffe-grpc-server", "", "The hub gRPC server's host:port.")
	fs.StringVar(&s.caBundleFile, "spiffe-ca-bundle", "", "PEM file with the hub CA certificate(s).")
	fs.StringSliceVar(&s.caFingerprints, "spiffe-ca-fingerprint", nil,
		"SHA-256 fingerprint of a hub CA certificate, obtained over a channel separate from the hub. Repeat during a hub CA rotation.")
	fs.StringVar(&s.identityFile, "spiffe-identity-file", "",
		"Where to write the identity file for the hub admin. Defaults to <cluster name>-identity.yaml.")
	fs.BoolVar(&s.pinIssuerKeys, "spiffe-pin-issuer-keys", true,
		"Pin this cluster's token issuer keys in the identity file, so the hub never contacts the issuer.")
}

func (o *Options) spiffeEnabled() bool {
	return o.spiffe.trustDomain != ""
}

// completeSPIFFE replaces the token-based hub client setup.
func (o *Options) completeSPIFFE() error {
	data, err := os.ReadFile(o.spiffe.caBundleFile)
	if err != nil {
		return fmt.Errorf("--spiffe-ca-bundle %q read failed: %w", o.spiffe.caBundleFile, err)
	}
	if o.spiffe.caBundle, err = spiffehelpers.ParseCertificates(data); err != nil {
		return fmt.Errorf("--spiffe-ca-bundle %q: %w", o.spiffe.caBundleFile, err)
	}
	o.registrationAuth = operatorv1.GRPCAuthType
	o.klusterletChartConfig.Klusterlet.RegistrationConfiguration.RegistrationDriver = operatorv1.RegistrationDriver{
		AuthType: operatorv1.GRPCAuthType,
		SPIFFE: &operatorv1.SPIFFEAgentConfig{
			GRPCServerAddress: o.spiffe.grpcServer,
			TrustDomain:       o.spiffe.trustDomain,
			TokenAudience:     o.spiffe.tokenAudience,
		},
	}
	if o.spiffe.identityFile == "" {
		o.spiffe.identityFile = o.clusterName + "-identity.yaml"
	}
	return nil
}

func (o *Options) validateSPIFFE(ctx context.Context) error {
	if err := preflightinterface.RunChecks(ctx, []preflightinterface.Checker{
		preflight.ClusterNameCheck{ClusterName: o.klusterletChartConfig.Klusterlet.ClusterName},
	}, os.Stderr); err != nil {
		return err
	}
	if o.spiffe.grpcServer == "" || o.spiffe.tokenAudience == "" || o.spiffe.caBundleFile == "" {
		return fmt.Errorf("--spiffe-grpc-server, --spiffe-token-audience and --spiffe-ca-bundle are required with --spiffe-trust-domain")
	}
	mode := o.klusterletChartConfig.Klusterlet.Mode
	if mode != operatorv1.InstallModeDefault && mode != operatorv1.InstallModeSingleton && mode != "" {
		return fmt.Errorf("SPIFFE identities are not supported in %s mode", mode)
	}
	// Stop before touching the cluster if the hub CA was swapped in transit.
	return spiffehelpers.VerifyCertificates(o.spiffe.caBundle, o.spiffe.caFingerprints)
}

// runSPIFFE stores the verified hub CA certificates in the cluster's
// ClusterTrustBundle, installs the klusterlet without Secrets, and writes the
// identity file for the hub admin.
func (o *Options) runSPIFFE(ctx context.Context, r *reader.ResourceReader, apply func() error) error {
	kubeClient, err := o.ClusteradmFlags.KubectlFactory.KubernetesClientSet()
	if err != nil {
		return err
	}
	if !o.ClusteradmFlags.DryRun {
		if err := trustbundle.NewPublisher(kubeClient.CertificatesV1beta1()).Publish(ctx, o.spiffe.caBundle); err != nil {
			return fmt.Errorf("failed to store the hub trust bundle (the cluster needs Kubernetes 1.35 or later with "+
				"the ClusterTrustBundle API): %w", err)
		}
	}
	if err := apply(); err != nil {
		return err
	}
	if o.ClusteradmFlags.DryRun {
		return nil
	}

	mcid, thumbprints, err := o.buildIdentity(ctx, kubeClient)
	if err != nil {
		return err
	}
	data, err := spiffehelpers.MarshalIdentityFile(mcid, thumbprints)
	if err != nil {
		return err
	}
	if err := os.WriteFile(o.spiffe.identityFile, data, 0o600); err != nil {
		return err
	}

	if len(o.outputFile) > 0 {
		if err := os.WriteFile(o.outputFile, r.RawAppliedResources(), 0o755); err != nil {
			return err
		}
	}

	fmt.Fprintf(o.Streams.Out, "The klusterlet is installed with SPIFFE identities; no Secret was created.\n\n"+
		"Send %s to the hub admin over an authenticated channel, and confirm these issuer key thumbprints with them over a second channel:\n\n",
		o.spiffe.identityFile)
	for _, t := range thumbprints {
		fmt.Fprintf(o.Streams.Out, "    %s\n", t)
	}
	fmt.Fprintf(o.Streams.Out, "\nThe hub admin then runs:\n\n"+
		"    %s accept --clusters %s --identity-file %s --identity-thumbprints %s\n\n"+
		"Until then the agents keep retrying and the hub answers not ready.\n",
		helpers.GetExampleHeader(), o.clusterName, o.spiffe.identityFile, strings.Join(thumbprints, ","))
	return nil
}

// buildIdentity reads the cluster's token issuer and keys and the UIDs of the
// agent ServiceAccounts the klusterlet operator creates.
func (o *Options) buildIdentity(ctx context.Context, kubeClient kubernetes.Interface) (*clusterv1alpha1.ManagedClusterIdentity, []string, error) {
	discovery, err := kubeClient.CoreV1().RESTClient().Get().AbsPath("/.well-known/openid-configuration").DoRaw(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read the cluster's ServiceAccount issuer: %w", err)
	}
	var config struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(discovery, &config); err != nil || config.Issuer == "" {
		return nil, nil, fmt.Errorf("the cluster's issuer discovery document has no issuer")
	}
	jwks, err := kubeClient.CoreV1().RESTClient().Get().AbsPath("/openid/v1/jwks").DoRaw(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read the cluster's issuer keys: %w", err)
	}
	thumbprints, err := spiffehelpers.Thumbprints(jwks)
	if err != nil {
		return nil, nil, err
	}

	namespace := o.klusterletChartConfig.Klusterlet.Namespace
	name := o.klusterletChartConfig.Klusterlet.Name
	// The singleton agent runs registration and work as the work
	// ServiceAccount, so that ServiceAccount carries the registration identity.
	agents := map[string]string{name + "-registration-sa": "registration", name + "-work-sa": "work"}
	if o.klusterletChartConfig.Klusterlet.Mode == operatorv1.InstallModeSingleton {
		agents = map[string]string{name + "-work-sa": "registration"}
	}

	mcid := &clusterv1alpha1.ManagedClusterIdentity{
		ObjectMeta: metav1.ObjectMeta{Name: o.clusterName},
		Spec:       clusterv1alpha1.ManagedClusterIdentitySpec{Issuer: config.Issuer},
	}
	if o.spiffe.pinIssuerKeys {
		mcid.Spec.JWKS = string(jwks)
	}
	fmt.Fprintf(o.Streams.Out, "Waiting for the klusterlet operator to create the agent ServiceAccounts...\n")
	for saName, agent := range agents {
		var uid string
		err := wait.PollUntilContextTimeout(ctx, 2*time.Second, time.Duration(o.ClusteradmFlags.Timeout)*time.Second, true,
			func(ctx context.Context) (bool, error) {
				sa, err := kubeClient.CoreV1().ServiceAccounts(namespace).Get(ctx, saName, metav1.GetOptions{})
				if err != nil {
					return false, nil
				}
				uid = string(sa.UID)
				return true, nil
			})
		if err != nil {
			return nil, nil, fmt.Errorf("ServiceAccount %s/%s was not created: %w", namespace, saName, err)
		}
		mcid.Spec.ServiceAccounts = append(mcid.Spec.ServiceAccounts, clusterv1alpha1.BoundServiceAccount{
			Namespace: namespace, Name: saName, UID: uid, Agent: agent,
		})
	}
	return mcid, thumbprints, nil
}
