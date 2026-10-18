package x509

// Making the key pair and the request we send to STS.
//
// The private key stays on the node. It goes to the workload that asked for it, never
// to STS, to disk, or to a log.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	cryptox509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// pemTypeCertificateRequest is the label in the "-----BEGIN ...-----" line of a
// certificate request. The name is fixed by RFC 7468.
const pemTypeCertificateRequest = "CERTIFICATE REQUEST"

// csrPlaceholderCommonName is a stand-in subject carried only to work around an STS
// defect: GetWorkloadIdentityCertificate currently fails on a CSR with an empty subject,
// reporting its own minted certificate as unparseable, so no certificate can be issued at
// all.
//
// TODO(workload-identity): drop this and go back to an empty subject once the STS fix
// ships. Nothing else in the agent depends on it.
const csrPlaceholderCommonName = "eks-pod-identity-agent"

// generateKey creates a new key pair of the configured kind for one certificate.
//
// It returns a crypto.Signer rather than the key, because a Signer does not expose the
// secret as bytes. An unknown kind is an error rather than a fallback: the kind is checked
// at startup, so reaching here with an unknown one means a caller skipped that check.
func generateKey(kind workloadidentity.KeyType) (crypto.Signer, error) {
	switch kind {
	case workloadidentity.KeyTypeECP256:
		return ecdsaKey(elliptic.P256(), kind)
	case workloadidentity.KeyTypeECP384:
		return ecdsaKey(elliptic.P384(), kind)
	case workloadidentity.KeyTypeRSA2048:
		return rsaKey(2048, kind)
	case workloadidentity.KeyTypeRSA4096:
		// Slow enough to notice. The agent generates a key for every pod at every
		// renewal, which is why the default is an elliptic curve.
		return rsaKey(4096, kind)
	default:
		return nil, fmt.Errorf("cannot generate a %q key: %w", string(kind), kind.Validate())
	}
}

func ecdsaKey(curve elliptic.Curve, kind workloadidentity.KeyType) (crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating a %s key: %w", string(kind), err)
	}
	return key, nil
}

func rsaKey(bits int, kind workloadidentity.KeyType) (crypto.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("generating a %s key: %w", string(kind), err)
	}
	return key, nil
}

// buildCSR creates the certificate request we send to STS. It carries the public half of
// the key pair and a signature made with the private half, which proves possession.
//
// The subject is a placeholder, not a name we are asking for. STS takes the subject from
// the attested workload identity in the session and ignores anything named here; the
// value is present only because an empty subject currently fails issuance outright. See
// csrPlaceholderCommonName.
func buildCSR(key crypto.Signer) (string, error) {
	der, err := cryptox509.CreateCertificateRequest(rand.Reader, &cryptox509.CertificateRequest{
		Subject: pkix.Name{CommonName: csrPlaceholderCommonName},
	}, key)
	if err != nil {
		return "", fmt.Errorf("building the certificate signing request: %w", err)
	}
	// EncodeToMemory cannot fail here. It returns nil rather than an error, and the only
	// thing that makes it do so is a header key containing a colon; we pass no headers.
	return string(pem.EncodeToMemory(&pem.Block{Type: pemTypeCertificateRequest, Bytes: der})), nil
}
