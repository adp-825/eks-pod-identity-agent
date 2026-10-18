// Command wi-client is a throwaway integration probe for the agent's SPIFFE
// Workload API. It is dev tooling for hack/dev, not part of the shipped agent.
//
// It runs four steps against the socket and reports each one separately, so a
// failure names the RPC that produced it rather than "workload identity broke":
//
//	1. FetchJWTSVID     - mints the JWT-SVID. This is the call that reaches STS
//	                      GetWebIdentityToken, signed with the workload's own
//	                      credentials, so it is the one that exercises the STS
//	                      endpoint override.
//	2. FetchJWTBundles  - the JWT authorities, i.e. the material step 3 needs.
//	3. ParseAndValidate - the pod verifies the token itself, cryptographically,
//	                      against those authorities. This is the actual proof the
//	                      JWT is good; step 1 only proves bytes came back.
//	4. ValidateJWTSVID  - the agent's own validation of the same token, as a
//	                      cross-check against step 3.
//
// Exits non-zero on the first failing step.
package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc/status"
)

// defaultAudience is overridden with WI_AUDIENCE. STS requires a nonblank
// audience, and the SPIFFE API requires at least one.
const defaultAudience = "wise-integ-test"

func main() {
	if err := run(); err != nil {
		fmt.Printf("\nRESULT: FAIL - %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\nRESULT: PASS - JWT-SVID fetched and verified by the pod\n")
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	audience := os.Getenv("WI_AUDIENCE")
	if audience == "" {
		audience = defaultAudience
	}

	// The env var and the mounted socket are the two things we inject by hand
	// instead of letting the webhook do it, so check them before blaming an RPC.
	socket := os.Getenv("SPIFFE_ENDPOINT_SOCKET")
	if socket == "" {
		return fmt.Errorf("SPIFFE_ENDPOINT_SOCKET is not set: the env var is missing from the pod spec")
	}
	fmt.Printf("socket:   %s\n", socket)
	fmt.Printf("audience: %s\n", audience)

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

	// Step 1: the mint. Reaches STS GetWebIdentityToken.
	fmt.Printf("\n--- step 1: FetchJWTSVID ---\n")
	svid, err := client.FetchJWTSVID(ctx, jwtsvid.Params{Audience: audience})
	if err != nil {
		return fmt.Errorf("step 1 FetchJWTSVID: %s", describe(err))
	}
	fmt.Printf("ok: spiffe id   = %s\n", svid.ID)
	fmt.Printf("ok: audience    = %v\n", svid.Audience)
	fmt.Printf("ok: expiry      = %s (in %s)\n", svid.Expiry.UTC().Format(time.RFC3339), time.Until(svid.Expiry).Round(time.Second))
	fmt.Printf("ok: trustdomain = %s\n", svid.ID.TrustDomain())
	printClaims("claims", svid.Claims)

	token := svid.Marshal()
	fmt.Printf("ok: token       = %d bytes\n", len(token))
	// A JWT-SVID is a live bearer credential. Printed only because this is a
	// throwaway probe on a test cluster, and only for its short lifetime.
	fmt.Printf("ok: raw token   = %s\n", token)

	// Step 2: the authorities step 3 verifies against.
	fmt.Printf("\n--- step 2: FetchJWTBundles ---\n")
	bundles, err := client.FetchJWTBundles(ctx)
	if err != nil {
		return fmt.Errorf("step 2 FetchJWTBundles: %s", describe(err))
	}
	for _, b := range bundles.Bundles() {
		authorities := b.JWTAuthorities()
		fmt.Printf("ok: trust domain %-28s jwt authorities=%d\n", b.TrustDomain(), len(authorities))
		// Printed per key, in kid order, because "authorities=2" does not say
		// whether the one that signed our token is among them.
		for _, kid := range sortedKeys(authorities) {
			fmt.Printf("ok:   authority kid=%s %s spki-sha256=%s\n",
				kid, publicKeyDescription(authorities[kid]), spkiFingerprint(authorities[kid]))
		}
	}

	// Step 3: the pod verifies the token itself. This is the real assertion:
	// signature checked against the agent-served authorities, audience enforced.
	fmt.Printf("\n--- step 3: ParseAndValidate (pod-side verification) ---\n")
	verified, err := jwtsvid.ParseAndValidate(token, bundles, []string{audience})
	if err != nil {
		return fmt.Errorf("step 3 ParseAndValidate: the pod could not verify the JWT: %w", err)
	}
	fmt.Printf("ok: signature verified against the trust bundle\n")
	fmt.Printf("ok: verified id = %s\n", verified.ID)
	fmt.Printf("ok: audience    = %v\n", verified.Audience)
	if verified.ID != svid.ID {
		return fmt.Errorf("step 3 ParseAndValidate: verified id %s does not match fetched id %s", verified.ID, svid.ID)
	}
	// Name the key that did it. ParseAndValidate picks the authority by the
	// token's kid, so this is the join between what STS signed with and what
	// the bundle API served, which is the whole point of the bundle call.
	header, err := tokenHeader(token)
	if err != nil {
		return fmt.Errorf("step 3 ParseAndValidate: reading the token header: %w", err)
	}
	fmt.Printf("ok: token header alg=%s kid=%s\n", header.Alg, header.Kid)
	bundle, err := bundles.GetJWTBundleForTrustDomain(svid.ID.TrustDomain())
	if err != nil {
		return fmt.Errorf("step 3 ParseAndValidate: no bundle for trust domain %s: %w", svid.ID.TrustDomain(), err)
	}
	signing, ok := bundle.FindJWTAuthority(header.Kid)
	if !ok {
		return fmt.Errorf("step 3 ParseAndValidate: the bundle has no authority for kid %s, "+
			"so the token was verified by a key the bundle API did not serve", header.Kid)
	}
	fmt.Printf("ok: signing authority found in the fetched bundle: kid=%s %s spki-sha256=%s\n",
		header.Kid, publicKeyDescription(signing), spkiFingerprint(signing))

	// Step 4: cross-check with the agent's own validation of the same token.
	fmt.Printf("\n--- step 4: ValidateJWTSVID (agent-side cross-check) ---\n")
	agentVerified, err := client.ValidateJWTSVID(ctx, token, audience)
	if err != nil {
		return fmt.Errorf("step 4 ValidateJWTSVID: %s", describe(err))
	}
	fmt.Printf("ok: agent validated the token, id = %s\n", agentVerified.ID)

	return nil
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

// printClaims prints claims in a stable order so two runs can be diffed.
func printClaims(label string, claims map[string]interface{}) {
	keys := make([]string, 0, len(claims))
	for k := range claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v, err := json.Marshal(claims[k])
		if err != nil {
			fmt.Printf("ok: %s.%s = <unprintable: %v>\n", label, k, err)
			continue
		}
		fmt.Printf("ok: %s.%s = %s\n", label, k, v)
	}
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

// jwtHeader is the part of a JWT header this probe reports: the algorithm STS
// signed with and the key id that selects the verifying authority.
type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// tokenHeader decodes the first segment of a compact JWT. Decoded by hand rather
// than with a JWT library because the token has already been verified by then,
// and this is only here to report what verified it.
func tokenHeader(token string) (jwtHeader, error) {
	var header jwtHeader
	segment, _, found := strings.Cut(token, ".")
	if !found {
		return header, fmt.Errorf("the token is not in compact JWT form")
	}
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return header, fmt.Errorf("decoding the header segment: %w", err)
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return header, fmt.Errorf("parsing the header JSON: %w", err)
	}
	return header, nil
}

// sortedKeys gives the authorities a stable print order so two runs can be diffed.
func sortedKeys(authorities map[string]crypto.PublicKey) []string {
	keys := make([]string, 0, len(authorities))
	for k := range authorities {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func publicKeyDescription(key crypto.PublicKey) string {
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

// spkiFingerprint identifies a bare public key the way a certificate
// fingerprint identifies a certificate, so the same authority can be recognised
// across runs and against the JWKS.
func spkiFingerprint(key crypto.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return fmt.Sprintf("(unmarshalable: %v)", err)
	}
	sum := sha256.Sum256(der)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}
