// Copyright Contributors to the Open Cluster Management project
package init

import (
	"fmt"
	"os"

	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	operatorv1 "open-cluster-management.io/api/operator/v1"
	"open-cluster-management.io/clusteradm/pkg/helpers"
)

// GRPCIdentitySPIFFE switches the gRPC driver to SPIFFE identities.
const GRPCIdentitySPIFFE = "spiffe"

// spiffeOptions configure SPIFFE identities for the gRPC driver. The hub CA
// key lives in an external KMS; no CA key, serving key or bootstrap token is
// stored on the hub.
type spiffeOptions struct {
	grpcIdentity              string
	trustDomain               string
	tokenAudience             string
	dnsNames                  []string
	agentSVIDLifetime         metav1.Duration
	serviceAccountAnnotations map[string]string
	podLabels                 map[string]string

	signerType string

	azureVaultURL        string
	azureCertificateName string

	openBaoAddress         string
	openBaoNamespace       string
	openBaoTransitMount    string
	openBaoKeyName         string
	openBaoCertificatePath string
	openBaoAuthMount       string
	openBaoAuthRole        string
	openBaoTokenAudience   string
}

func (s *spiffeOptions) addFlags(fs *pflag.FlagSet) {
	fs.StringVar(&s.grpcIdentity, "grpc-identity", "",
		"Identity mode of the grpc registration driver. Set to spiffe to use SPIFFE identities signed by a hub CA in an external KMS.")
	fs.StringVar(&s.trustDomain, "spiffe-trust-domain", "", "The hub's SPIFFE trust domain. Must be unique to this hub.")
	fs.StringVar(&s.tokenAudience, "spiffe-token-audience", "",
		"The audience agents request on their projected tokens. Must be unique to this hub. Defaults to open-cluster-management.io/<trust domain>.")
	fs.StringSliceVar(&s.dnsNames, "spiffe-dns-names", nil, "DNS names to add to the hub server SVID.")
	fs.DurationVar(&s.agentSVIDLifetime.Duration, "spiffe-agent-svid-lifetime", 0, "Lifetime of agent SVIDs. Defaults to 1h.")
	fs.StringToStringVar(&s.serviceAccountAnnotations, "spiffe-sa-annotations", nil,
		"Annotations for the gRPC server ServiceAccount, for example to link it to the KMS provider's workload identity.")
	fs.StringToStringVar(&s.podLabels, "spiffe-pod-labels", nil, "Labels for the gRPC server pods, for example azure.workload.identity/use=true.")
	fs.StringVar(&s.signerType, "spiffe-signer", "", "The KMS holding the hub CA key: AzureKeyVault or OpenBao.")
	fs.StringVar(&s.azureVaultURL, "spiffe-azure-vault-url", "", "Azure Key Vault URL, for example https://my-vault.vault.azure.net.")
	fs.StringVar(&s.azureCertificateName, "spiffe-azure-certificate", "", "Azure Key Vault certificate holding the hub CA.")
	fs.StringVar(&s.openBaoAddress, "spiffe-openbao-address", "", "OpenBao address, for example https://openbao.example.com:8200.")
	fs.StringVar(&s.openBaoNamespace, "spiffe-openbao-namespace", "", "OpenBao namespace, if namespaces are used.")
	fs.StringVar(&s.openBaoTransitMount, "spiffe-openbao-transit-mount", "", "OpenBao transit mount. Defaults to transit.")
	fs.StringVar(&s.openBaoKeyName, "spiffe-openbao-key", "", "Non-exportable OpenBao transit key holding the hub CA key.")
	fs.StringVar(&s.openBaoCertificatePath, "spiffe-openbao-certificate-path", "",
		"KV v2 API path of the secret holding the hub CA certificate, for example secret/data/ocm/spiffe-ca.")
	fs.StringVar(&s.openBaoAuthMount, "spiffe-openbao-auth-mount", "", "OpenBao Kubernetes auth mount. Defaults to kubernetes.")
	fs.StringVar(&s.openBaoAuthRole, "spiffe-openbao-auth-role", "", "OpenBao Kubernetes auth role bound to the gRPC server ServiceAccount.")
	fs.StringVar(&s.openBaoTokenAudience, "spiffe-openbao-token-audience", "", "Audience of the token presented to OpenBao. Defaults to openbao.")
}

func (s *spiffeOptions) enabled() bool {
	return s.grpcIdentity == GRPCIdentitySPIFFE
}

func (s *spiffeOptions) validate(registrationDrivers []string) error {
	if s.grpcIdentity == "" {
		return nil
	}
	if !s.enabled() {
		return fmt.Errorf("--grpc-identity must be %s", GRPCIdentitySPIFFE)
	}
	if !sets.New(registrationDrivers...).Has(operatorv1.GRPCAuthType) {
		return fmt.Errorf("--grpc-identity=spiffe requires the grpc registration driver")
	}
	if s.trustDomain == "" {
		return fmt.Errorf("--spiffe-trust-domain is required")
	}
	switch operatorv1.SPIFFESignerType(s.signerType) {
	case operatorv1.SPIFFESignerTypeAzureKeyVault:
		if s.azureVaultURL == "" || s.azureCertificateName == "" {
			return fmt.Errorf("--spiffe-azure-vault-url and --spiffe-azure-certificate are required for the AzureKeyVault signer")
		}
	case operatorv1.SPIFFESignerTypeOpenBao:
		if s.openBaoAddress == "" || s.openBaoKeyName == "" || s.openBaoCertificatePath == "" || s.openBaoAuthRole == "" {
			return fmt.Errorf("--spiffe-openbao-address, --spiffe-openbao-key, --spiffe-openbao-certificate-path and " +
				"--spiffe-openbao-auth-role are required for the OpenBao signer")
		}
	default:
		return fmt.Errorf("--spiffe-signer must be %s or %s", operatorv1.SPIFFESignerTypeAzureKeyVault, operatorv1.SPIFFESignerTypeOpenBao)
	}
	return nil
}

func (s *spiffeOptions) audience() string {
	if s.tokenAudience != "" {
		return s.tokenAudience
	}
	return "open-cluster-management.io/" + s.trustDomain
}

func (s *spiffeOptions) hubConfig() *operatorv1.SPIFFEHubConfig {
	cfg := &operatorv1.SPIFFEHubConfig{
		TrustDomain:               s.trustDomain,
		TokenAudience:             s.audience(),
		DNSNames:                  s.dnsNames,
		ServiceAccountAnnotations: s.serviceAccountAnnotations,
		PodLabels:                 s.podLabels,
		Signer:                    operatorv1.SPIFFESigner{Type: operatorv1.SPIFFESignerType(s.signerType)},
	}
	if s.agentSVIDLifetime.Duration > 0 {
		lifetime := s.agentSVIDLifetime
		cfg.AgentSVIDLifetime = &lifetime
	}
	switch cfg.Signer.Type {
	case operatorv1.SPIFFESignerTypeAzureKeyVault:
		cfg.Signer.AzureKeyVault = &operatorv1.AzureKeyVaultSigner{
			VaultURL:        s.azureVaultURL,
			CertificateName: s.azureCertificateName,
		}
	case operatorv1.SPIFFESignerTypeOpenBao:
		cfg.Signer.OpenBao = &operatorv1.OpenBaoSigner{
			Address:         s.openBaoAddress,
			Namespace:       s.openBaoNamespace,
			TransitMount:    s.openBaoTransitMount,
			KeyName:         s.openBaoKeyName,
			CertificatePath: s.openBaoCertificatePath,
			AuthMount:       s.openBaoAuthMount,
			AuthRole:        s.openBaoAuthRole,
			TokenAudience:   s.openBaoTokenAudience,
		}
	}
	return cfg
}

// spiffeJoinCommand is printed instead of a token-based join command. It
// carries only public data; the hub CA fingerprint must travel separately.
func (o *Options) spiffeJoinCommand() string {
	return fmt.Sprintf("%s join --registration-auth grpc --spiffe-grpc-server %s --spiffe-trust-domain %s "+
		"--spiffe-token-audience %s --spiffe-ca-bundle hub-ca.pem --spiffe-ca-fingerprint <hub CA fingerprint>",
		helpers.GetExampleHeader(), o.grpcServer, o.spiffe.trustDomain, o.spiffe.audience())
}

func (o *Options) printSPIFFEJoinCommand() error {
	cmd := o.spiffeJoinCommand()
	if len(o.outputJoinCommandFile) > 0 {
		if err := os.WriteFile(o.outputJoinCommandFile, []byte(cmd+" --cluster-name $1"), 0o755); err != nil {
			return err
		}
	}
	fmt.Fprintf(o.Streams.Out, "The multicluster hub control plane has been initialized with SPIFFE identities.\n\n"+
		"No bootstrap token was created. To register a cluster:\n\n"+
		"  1. Save the hub trust bundle, which is public:\n\n"+
		"       kubectl get clustertrustbundle open-cluster-management.io:spiffe-hub:ca -o jsonpath='{.spec.trustBundle}' > hub-ca.pem\n\n"+
		"  2. Give the cluster admin hub-ca.pem and this command, and the hub CA fingerprint from the KMS admin over a separate channel:\n\n"+
		"       %s --cluster-name <cluster_name>\n\n"+
		"  3. Accept the cluster with the identity file the join produces:\n\n"+
		"       %s accept --clusters <cluster_name> --identity-file <cluster_name>-identity.yaml --identity-thumbprints <thumbprints>\n\n",
		cmd, helpers.GetExampleHeader())
	return nil
}
