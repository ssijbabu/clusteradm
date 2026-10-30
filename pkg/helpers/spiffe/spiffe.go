// Copyright Contributors to the Open Cluster Management project

// Package spiffe holds what clusteradm join and accept share for SPIFFE
// identities: checking the hub CA certificates against fingerprints shared
// out of band, and the identity file that binds a managed cluster's token
// issuer and agent ServiceAccounts on the hub.
package spiffe

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"

	clusterv1alpha1 "open-cluster-management.io/api/cluster/v1alpha1"
)

// ParseCertificates parses concatenated PEM CERTIFICATE blocks.
func ParseCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no PEM certificates found")
	}
	return certs, nil
}

// Fingerprint returns the SHA-256 fingerprint of a certificate as
// sha256:<lowercase hex>.
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// NormalizeFingerprint accepts sha256:<hex>, plain hex, upper case and
// colon-separated hex, as tools print fingerprints in different forms.
func NormalizeFingerprint(f string) string {
	f = strings.ToLower(strings.TrimSpace(f))
	f = strings.TrimPrefix(f, "sha256:")
	f = strings.ReplaceAll(f, ":", "")
	return "sha256:" + f
}

// VerifyCertificates checks that every certificate matches one of the
// fingerprints. Every certificate must match, so nobody can slip an extra CA
// into a bundle next to the genuine one.
func VerifyCertificates(certs []*x509.Certificate, fingerprints []string) error {
	if len(fingerprints) == 0 {
		return fmt.Errorf("at least one hub CA fingerprint is required")
	}
	allowed := map[string]bool{}
	for _, f := range fingerprints {
		allowed[NormalizeFingerprint(f)] = true
	}
	for _, c := range certs {
		if !allowed[Fingerprint(c)] {
			return fmt.Errorf("hub CA certificate %q has fingerprint %s, which does not match the fingerprint shared out of band; "+
				"do not join this hub until the fingerprint is confirmed", c.Subject.String(), Fingerprint(c))
		}
		if !c.IsCA {
			return fmt.Errorf("certificate %q in the hub trust bundle is not a CA certificate", c.Subject.String())
		}
	}
	return nil
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

// Thumbprints returns the RFC 7638 SHA-256 thumbprint of each key in a JSON
// Web Key Set, sorted. Admins compare these over a second channel.
func Thumbprints(jwks []byte) ([]string, error) {
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &set); err != nil {
		return nil, fmt.Errorf("invalid JWKS: %w", err)
	}
	var out []string
	for _, k := range set.Keys {
		var canonical string
		switch k.Kty {
		case "EC":
			canonical = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, k.Crv, k.X, k.Y)
		case "RSA":
			canonical = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, k.E, k.N)
		default:
			continue
		}
		sum := sha256.Sum256([]byte(canonical))
		out = append(out, base64.RawURLEncoding.EncodeToString(sum[:]))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("JWKS has no EC or RSA keys")
	}
	sort.Strings(out)
	return out, nil
}

// MarshalIdentityFile renders a ManagedClusterIdentity with the issuer key
// thumbprints in a header comment.
func MarshalIdentityFile(mcid *clusterv1alpha1.ManagedClusterIdentity, thumbprints []string) ([]byte, error) {
	mcid.TypeMeta.APIVersion = clusterv1alpha1.GroupVersion.String()
	mcid.TypeMeta.Kind = "ManagedClusterIdentity"
	data, err := yaml.Marshal(mcid)
	if err != nil {
		return nil, err
	}
	header := "# Identity file for managed cluster " + mcid.Name + ".\n" +
		"# Send it to the hub admin over an authenticated channel, and confirm these\n" +
		"# issuer key thumbprints with them over a second channel:\n"
	for _, t := range thumbprints {
		header += "#   " + t + "\n"
	}
	return append([]byte(header), data...), nil
}

// UnmarshalIdentityFile parses an identity file and checks its pinned keys
// match the thumbprints the admins confirmed out of band.
func UnmarshalIdentityFile(data []byte, confirmedThumbprints []string) (*clusterv1alpha1.ManagedClusterIdentity, error) {
	mcid := &clusterv1alpha1.ManagedClusterIdentity{}
	if err := yaml.UnmarshalStrict(data, mcid); err != nil {
		return nil, fmt.Errorf("invalid identity file: %w", err)
	}
	if mcid.Name == "" || mcid.Spec.Issuer == "" || len(mcid.Spec.ServiceAccounts) == 0 {
		return nil, fmt.Errorf("identity file must name the cluster, its issuer and its agent ServiceAccounts")
	}
	if !strings.HasPrefix(mcid.Spec.Issuer, "https://") {
		return nil, fmt.Errorf("issuer %q must be an https URL", mcid.Spec.Issuer)
	}
	if mcid.Spec.JWKS == "" {
		return mcid, nil
	}
	got, err := Thumbprints([]byte(mcid.Spec.JWKS))
	if err != nil {
		return nil, err
	}
	want := append([]string{}, confirmedThumbprints...)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		return nil, fmt.Errorf("the identity file's issuer key thumbprints %v do not match the confirmed thumbprints %v; "+
			"confirm them with the managed cluster admin over a second channel", got, want)
	}
	return mcid, nil
}
