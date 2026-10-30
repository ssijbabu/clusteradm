// Copyright Contributors to the Open Cluster Management project
package spiffe

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	clusterv1alpha1 "open-cluster-management.io/api/cluster/v1alpha1"
	"open-cluster-management.io/ocm/pkg/server/spiffe/signer/memory"
)

// rfc7638Key is the example key from RFC 7638 section 3.1, whose thumbprint
// is NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs.
const rfc7638Key = `{"keys":[{"kty":"RSA","kid":"2011-04-29","e":"AQAB","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}]}`

func newCA(t *testing.T) *x509.Certificate {
	t.Helper()
	_, cert, err := memory.NewSelfSignedCA("hub1.example.org", time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestVerifyCertificates(t *testing.T) {
	genuine, extra := newCA(t), newCA(t)
	fp := Fingerprint(genuine)

	if err := VerifyCertificates([]*x509.Certificate{genuine}, []string{fp}); err != nil {
		t.Fatalf("genuine hub CA refused: %v", err)
	}
	// Fingerprints are accepted in the forms tools print them.
	hexOnly := strings.TrimPrefix(fp, "sha256:")
	var colons []string
	for i := 0; i < len(hexOnly); i += 2 {
		colons = append(colons, strings.ToUpper(hexOnly[i:i+2]))
	}
	if err := VerifyCertificates([]*x509.Certificate{genuine}, []string{strings.Join(colons, ":")}); err != nil {
		t.Errorf("colon-separated upper-case fingerprint refused: %v", err)
	}
	if err := VerifyCertificates([]*x509.Certificate{genuine, extra}, []string{fp}); err == nil {
		t.Error("an extra CA next to the genuine one must be refused")
	}
	if err := VerifyCertificates([]*x509.Certificate{extra}, []string{fp}); err == nil {
		t.Error("a swapped hub CA must be refused")
	}
	if err := VerifyCertificates([]*x509.Certificate{genuine, extra}, []string{fp, Fingerprint(extra)}); err != nil {
		t.Errorf("both CAs confirmed during a rotation must be accepted: %v", err)
	}
	if err := VerifyCertificates([]*x509.Certificate{genuine}, nil); err == nil {
		t.Error("a missing fingerprint must be refused")
	}
}

func TestParseCertificates(t *testing.T) {
	a, b := newCA(t), newCA(t)
	data := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b.Raw})...)
	certs, err := ParseCertificates(data)
	if err != nil || len(certs) != 2 {
		t.Fatalf("want 2 certificates, got %d, %v", len(certs), err)
	}
	if _, err := ParseCertificates([]byte("not pem")); err == nil {
		t.Error("expected an error without certificates")
	}
}

func TestThumbprintsMatchRFC7638(t *testing.T) {
	got, err := Thumbprints([]byte(rfc7638Key))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Fatalf("unexpected thumbprint %v", got)
	}
}

func TestIdentityFileRoundTrip(t *testing.T) {
	mcid := &clusterv1alpha1.ManagedClusterIdentity{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster1"},
		Spec: clusterv1alpha1.ManagedClusterIdentitySpec{
			Issuer: "https://spoke1.example.org",
			JWKS:   rfc7638Key,
			ServiceAccounts: []clusterv1alpha1.BoundServiceAccount{
				{Namespace: "open-cluster-management-agent", Name: "klusterlet-registration-sa", UID: "u1", Agent: "registration"},
			},
		},
	}
	thumbprints, _ := Thumbprints([]byte(rfc7638Key))
	data, err := MarshalIdentityFile(mcid, thumbprints)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), thumbprints[0]) {
		t.Error("identity file does not show the thumbprints")
	}

	got, err := UnmarshalIdentityFile(data, thumbprints)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "cluster1" || got.Spec.ServiceAccounts[0].UID != "u1" || got.Spec.JWKS != rfc7638Key {
		t.Errorf("identity file did not round-trip: %+v", got)
	}
	if _, err := UnmarshalIdentityFile(data, []string{"not-the-confirmed-thumbprint"}); err == nil {
		t.Error("a thumbprint mismatch must be refused")
	}

	mcid.Spec.Issuer = "http://spoke1.example.org"
	data, _ = MarshalIdentityFile(mcid, thumbprints)
	if _, err := UnmarshalIdentityFile(data, thumbprints); err == nil {
		t.Error("a plain-http issuer must be refused")
	}
}
