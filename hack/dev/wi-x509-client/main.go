// Command wi-x509-client is a throwaway integration probe for the agent's
// X.509-SVID path, the sibling of wi-client. It is dev tooling for hack/dev, not
// part of the shipped agent.
//
// It runs four steps against the socket and reports each one separately, so a
// failure names the RPC that produced it rather than "workload identity broke":
//
//	1. FetchX509Bundles - the X.509 authorities. Deliberately first, because it
//	                      is independent of issuance: while STS cannot issue a
//	                      certificate (see integration-findings.md finding 4),
//	                      this is the only part of the X.509 path that can be
//	                      exercised, and ordering it after the mint would hide it
//	                      behind that failure.
//	2. FetchX509SVID    - mints the X.509-SVID. This is the call that reaches STS
//	                      GetWorkloadIdentityCertificate, signed with the
//	                      workload's own credentials, so it is the one that
//	                      exercises the STS endpoint override.
//	3. key agreement    - the pod checks the returned private key against the
//	                      leaf's public key. STS only takes a public key and a
//	                      proof of possession, so this proves the two halves
//	                      actually belong together.
//	4. Verify           - the pod verifies the chain itself, cryptographically,
//	                      against the step 1 authorities. This is the actual
//	                      proof the certificate is good; step 2 only proves bytes
//	                      came back.
//
// Every certificate is printed in full, authorities and chain alike, because the
// point of the probe is to see what STS actually issued.
//
// Exits non-zero on the first failing step, after whatever earlier steps printed.
package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc/status"
)

func main() {
	if err := run(); err != nil {
		fmt.Printf("\nRESULT: FAIL - %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\nRESULT: PASS - X.509-SVID fetched and verified by the pod\n")
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// The env var and the mounted socket are the two things we inject by hand
	// instead of letting the webhook do it, so check them before blaming an RPC.
	socket := os.Getenv("SPIFFE_ENDPOINT_SOCKET")
	if socket == "" {
		return fmt.Errorf("SPIFFE_ENDPOINT_SOCKET is not set: the env var is missing from the pod spec")
	}
	fmt.Printf("socket:   %s\n", socket)

	if path, ok := socketPath(socket); ok {
		st, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("the socket %s is not present in the pod: %w (is the %s CSI volume mounted?)",
				path, err, "spiffe.csi.eks.amazonaws.com")
		}
		fmt.Printf("socket stat: mode=%s\n", st.Mode())
	}

	client, err := workloadapi.New(ctx, workloadapi.WithAddr(socket))
	if err != nil {
		return fmt.Errorf("step 0 dial: opening a Workload API client on %s: %w", socket, err)
	}
	defer func() { _ = client.Close() }()

	// Step 1: the authorities. First because it does not depend on issuance.
	fmt.Printf("\n--- step 1: FetchX509Bundles ---\n")
	bundles, err := client.FetchX509Bundles(ctx)
	if err != nil {
		return fmt.Errorf("step 1 FetchX509Bundles: %s", describe(err))
	}
	for _, b := range bundles.Bundles() {
		authorities := b.X509Authorities()
		fmt.Printf("ok: trust domain %s x509 authorities=%d\n", b.TrustDomain(), len(authorities))
		for i, cert := range authorities {
			printCert(fmt.Sprintf("authority[%d] of %s", i, b.TrustDomain()), cert)
		}
	}

	// Step 2: the mint. Reaches STS GetWorkloadIdentityCertificate. Given its own
	// deadline, well short of the overall one: the agent treats the current STS
	// failure as retryable and holds the stream open, so without this the probe
	// would sit in backoff until the whole run times out.
	fmt.Printf("\n--- step 2: FetchX509SVID ---\n")
	svidCtx, cancelSVID := context.WithTimeout(ctx, 20*time.Second)
	defer cancelSVID()
	svid, err := client.FetchX509SVID(svidCtx)
	if err != nil {
		return fmt.Errorf("step 2 FetchX509SVID: %s "+
			"(the agent log carries the STS cause; a repeating InternalFailure here is finding 4)", describe(err))
	}
	fmt.Printf("ok: spiffe id   = %s\n", svid.ID)
	fmt.Printf("ok: trustdomain = %s\n", svid.ID.TrustDomain())
	if svid.Hint != "" {
		fmt.Printf("ok: hint        = %s\n", svid.Hint)
	}
	fmt.Printf("ok: chain depth = %d certificate(s)\n", len(svid.Certificates))
	if len(svid.Certificates) == 0 {
		return fmt.Errorf("step 2 FetchX509SVID: the SVID carries no certificates")
	}
	for i, cert := range svid.Certificates {
		label := fmt.Sprintf("chain[%d]", i)
		if i == 0 {
			label += " (leaf, the SVID)"
		} else {
			label += " (intermediate)"
		}
		printCert(label, cert)
	}
	// The design says STS returns the chain without the root, the verifier
	// holding it from the trust bundle instead. Report what we actually got.
	last := svid.Certificates[len(svid.Certificates)-1]
	fmt.Printf("\nok: chain ends with %q, self-signed=%t (a root in the chain would be self-signed)\n",
		last.Subject.CommonName, isSelfSigned(last))

	// Step 3: the private key the agent generated has to match the leaf, since
	// STS signs over a public key it never sees the private half of.
	fmt.Printf("\n--- step 3: key agreement (private key vs leaf public key) ---\n")
	fmt.Printf("ok: private key = %s\n", keyDescription(svid.PrivateKey))
	if svid.PrivateKey == nil {
		return fmt.Errorf("step 3 key agreement: the SVID carries no private key")
	}
	leaf := svid.Certificates[0]
	if !publicKeysEqual(svid.PrivateKey.Public(), leaf.PublicKey) {
		return fmt.Errorf("step 3 key agreement: the private key does not match the leaf's public key")
	}
	fmt.Printf("ok: the private key matches the leaf's public key\n")

	// Step 4: the pod verifies the chain itself. This is the real assertion:
	// chain built and checked against the step 1 authorities.
	fmt.Printf("\n--- step 4: Verify (pod-side chain verification) ---\n")
	verifiedID, chains, err := x509svid.Verify(svid.Certificates, bundles)
	if err != nil {
		return fmt.Errorf("step 4 Verify: the pod could not verify the certificate chain: %w", err)
	}
	fmt.Printf("ok: chain verified against the trust bundle\n")
	fmt.Printf("ok: verified id = %s\n", verifiedID)
	for i, chain := range chains {
		names := make([]string, 0, len(chain))
		for _, cert := range chain {
			names = append(names, fmt.Sprintf("%q", cert.Subject.CommonName))
		}
		fmt.Printf("ok: verified chain[%d] = %s\n", i, strings.Join(names, " -> "))
	}
	if verifiedID != svid.ID {
		return fmt.Errorf("step 4 Verify: verified id %s does not match fetched id %s", verifiedID, svid.ID)
	}

	return nil
}

// printCert prints everything about a certificate that a reviewer of this probe
// would otherwise have to go and decode by hand, PEM included.
func printCert(label string, cert *x509.Certificate) {
	fmt.Printf("\n--- %s ---\n", label)
	fmt.Printf("  subject            = %s\n", nameOrEmpty(cert.Subject.String()))
	fmt.Printf("  issuer             = %s\n", nameOrEmpty(cert.Issuer.String()))
	fmt.Printf("  serial             = %s (0x%x)\n", cert.SerialNumber, cert.SerialNumber)
	fmt.Printf("  not before         = %s\n", cert.NotBefore.UTC().Format(time.RFC3339))
	fmt.Printf("  not after          = %s\n", cert.NotAfter.UTC().Format(time.RFC3339))
	fmt.Printf("  issued lifetime    = %s\n", cert.NotAfter.Sub(cert.NotBefore))
	fmt.Printf("  remaining          = %s\n", time.Until(cert.NotAfter).Round(time.Second))
	fmt.Printf("  version            = %d\n", cert.Version)
	fmt.Printf("  signature alg      = %s\n", cert.SignatureAlgorithm)
	fmt.Printf("  public key         = %s\n", publicKeyDescription(cert.PublicKey))
	fmt.Printf("  spki sha256        = %s\n", spkiFingerprint(cert))
	fmt.Printf("  cert sha256        = %s\n", colonHex(sha256.Sum256(cert.Raw)))
	fmt.Printf("  is CA              = %t (basic constraints valid=%t, max path len=%d)\n",
		cert.IsCA, cert.BasicConstraintsValid, cert.MaxPathLen)
	fmt.Printf("  key usage          = %s\n", keyUsage(cert.KeyUsage))
	fmt.Printf("  ext key usage      = %s\n", extKeyUsage(cert))
	fmt.Printf("  URI SANs           = %s\n", uriSANs(cert.URIs))
	fmt.Printf("  DNS SANs           = %s\n", listOrNone(cert.DNSNames))
	fmt.Printf("  IP SANs            = %s\n", ipSANs(cert.IPAddresses))
	fmt.Printf("  email SANs         = %s\n", listOrNone(cert.EmailAddresses))
	fmt.Printf("  subject key id     = %s\n", hexOrNone(cert.SubjectKeyId))
	fmt.Printf("  authority key id   = %s\n", hexOrNone(cert.AuthorityKeyId))
	fmt.Printf("  CRL dist points    = %s\n", listOrNone(cert.CRLDistributionPoints))
	fmt.Printf("  OCSP servers       = %s\n", listOrNone(cert.OCSPServer))
	fmt.Printf("  critical ext OIDs  = %s\n", oids(cert))
	fmt.Printf("  PEM:\n%s", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

func nameOrEmpty(s string) string {
	if s == "" {
		// STS ignores any subject in the CSR, so an empty one is expected: the
		// identity lives in the URI SAN, not the subject.
		return "(empty)"
	}
	return s
}

func listOrNone(values []string) string {
	if len(values) == 0 {
		return "(none)"
	}
	return strings.Join(values, ", ")
}

func uriSANs(uris []*url.URL) string {
	if len(uris) == 0 {
		return "(none)"
	}
	out := make([]string, 0, len(uris))
	for _, u := range uris {
		out = append(out, u.String())
	}
	return strings.Join(out, ", ")
}

func ipSANs(ips []net.IP) string {
	if len(ips) == 0 {
		return "(none)"
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return strings.Join(out, ", ")
}

func hexOrNone(b []byte) string {
	if len(b) == 0 {
		return "(none)"
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

func colonHex(sum [32]byte) string {
	out := make([]string, 0, len(sum))
	for _, b := range sum {
		out = append(out, fmt.Sprintf("%02X", b))
	}
	return strings.Join(out, ":")
}

func spkiFingerprint(cert *x509.Certificate) string {
	if len(cert.RawSubjectPublicKeyInfo) == 0 {
		return "(none)"
	}
	return colonHex(sha256.Sum256(cert.RawSubjectPublicKeyInfo))
}

func oids(cert *x509.Certificate) string {
	if len(cert.UnhandledCriticalExtensions) == 0 {
		return "(none unhandled)"
	}
	out := make([]string, 0, len(cert.UnhandledCriticalExtensions))
	for _, oid := range cert.UnhandledCriticalExtensions {
		out = append(out, oid.String())
	}
	return strings.Join(out, ", ")
}

func keyUsage(u x509.KeyUsage) string {
	names := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "DigitalSignature"},
		{x509.KeyUsageContentCommitment, "ContentCommitment"},
		{x509.KeyUsageKeyEncipherment, "KeyEncipherment"},
		{x509.KeyUsageDataEncipherment, "DataEncipherment"},
		{x509.KeyUsageKeyAgreement, "KeyAgreement"},
		{x509.KeyUsageCertSign, "CertSign"},
		{x509.KeyUsageCRLSign, "CRLSign"},
		{x509.KeyUsageEncipherOnly, "EncipherOnly"},
		{x509.KeyUsageDecipherOnly, "DecipherOnly"},
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if u&n.bit != 0 {
			out = append(out, n.name)
		}
	}
	return listOrNone(out)
}

func extKeyUsage(cert *x509.Certificate) string {
	names := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:             "Any",
		x509.ExtKeyUsageServerAuth:      "ServerAuth",
		x509.ExtKeyUsageClientAuth:      "ClientAuth",
		x509.ExtKeyUsageCodeSigning:     "CodeSigning",
		x509.ExtKeyUsageEmailProtection: "EmailProtection",
		x509.ExtKeyUsageTimeStamping:    "TimeStamping",
		x509.ExtKeyUsageOCSPSigning:     "OCSPSigning",
	}
	out := make([]string, 0, len(cert.ExtKeyUsage)+len(cert.UnknownExtKeyUsage))
	for _, u := range cert.ExtKeyUsage {
		if name, ok := names[u]; ok {
			out = append(out, name)
			continue
		}
		out = append(out, fmt.Sprintf("unnamed(%d)", u))
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		out = append(out, oid.String())
	}
	return listOrNone(out)
}

func publicKeyDescription(key any) string {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA %s (%d-bit)", k.Curve.Params().Name, k.Curve.Params().BitSize)
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d-bit (e=%d)", k.N.BitLen(), k.E)
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return fmt.Sprintf("%T", key)
	}
}

func keyDescription(signer crypto.Signer) string {
	if signer == nil {
		return "(none)"
	}
	return publicKeyDescription(signer.Public())
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	switch left := a.(type) {
	case *ecdsa.PublicKey:
		right, ok := b.(*ecdsa.PublicKey)
		return ok && left.Equal(right)
	case *rsa.PublicKey:
		right, ok := b.(*rsa.PublicKey)
		return ok && left.Equal(right)
	case ed25519.PublicKey:
		right, ok := b.(ed25519.PublicKey)
		return ok && left.Equal(right)
	default:
		return false
	}
}

func isSelfSigned(cert *x509.Certificate) bool {
	return cert.Subject.String() == cert.Issuer.String() &&
		cert.CheckSignatureFrom(cert) == nil
}

// socketPath returns the filesystem path of a unix:// endpoint, so a missing
// CSI mount is reported as such instead of as a dial failure.
func socketPath(addr string) (string, bool) {
	const scheme = "unix://"
	if len(addr) > len(scheme) && addr[:len(scheme)] == scheme {
		return addr[len(scheme):], true
	}
	return "", false
}

// describe spells out the gRPC status, because the code is what separates "this
// pod is not enrolled" (PermissionDenied) from "the upstream call failed"
// (Internal/Unavailable) and from "no socket" (Unavailable on dial).
func describe(err error) string {
	if st, ok := status.FromError(err); ok {
		return fmt.Sprintf("grpc code=%s message=%q", st.Code(), st.Message())
	}
	return err.Error()
}
