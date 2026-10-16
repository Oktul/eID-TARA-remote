// SPDX-License-Identifier: EUPL-1.2

package fit

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// Synthetic identifiers. None belongs to a real app, environment, site or
// installation (CONTRIBUTING.md, Tests).
const (
	synthAppID     = "ari:cloud:ecosystem::app/00000000-0000-4000-8000-000000000001"
	synthEnvID     = "00000000-0000-4000-8000-000000000002"
	synthInstallID = "ari:cloud:ecosystem::installation/00000000-0000-4000-8000-000000000003"
	synthSiteA     = "00000000-0000-4000-8000-00000000000a" // allowed
	synthSiteB     = "00000000-0000-4000-8000-00000000000b" // allowed
	synthSiteX     = "00000000-0000-4000-8000-0000000000ff" // not allowed
	synthKID       = "synthetic-key-1"
)

// The valid token, written as raw JSON so that cases can craft duplicate
// members, escapes and invalid UTF-8 by replacing one fragment. Fragments
// that are not last in their object end in a comma, so replacing one with
// "" removes the member.
const (
	validHeader = `{"alg":"RS256","kid":"` + synthKID + `","typ":"JWT"}`

	contextMember      = `"context":{"cloudId":"` + synthSiteA + `","moduleKey":"token-relay"},`
	envMember          = `"environment":{"type":"DEVELOPMENT","id":"` + synthEnvID + `"},`
	installIDMember    = `"installationId":"` + synthInstallID + `",`
	installationMember = `"installation":{"contexts":[{"cloudId":"` + synthSiteA + `"}]},`
	appIDMember        = `"id":"` + synthAppID + `"}`
	appMember          = `"app":{` + envMember + installIDMember + installationMember + appIDMember + `,`
	issMember          = `"iss":"forge/invocation-token",`
	audMember          = `"aud":"` + synthAppID + `",`
	expMember          = `"exp":1800000020,`
	nbfMember          = `"nbf":1799999995,`
	lastMember         = `"principal":"synthetic-principal"}`

	validPayload = `{` + contextMember + appMember + issMember + audMember + expMember + nbfMember +
		`"iat":1799999995,"jti":"synthetic-jti",` + lastMember
)

// synthNow is the verification time of every test: 5 s after the valid
// payload's nbf and 20 s before its exp.
var synthNow = time.Unix(1800000000, 0)

var validClaims = Claims{CloudID: synthSiteA}

// testSigners are generated once per test run, so no private key is ever
// committed (CONTRIBUTING.md, Tests).
type testSigners struct {
	primary *rsa.PrivateKey // published under synthKID
	other   *rsa.PrivateKey // never published
}

var signers = sync.OnceValue(func() testSigners {
	gen := func() *rsa.PrivateKey {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		return k
	}
	return testSigners{primary: gen(), other: gen()}
})

// keyFunc adapts a function to keySource, standing in for the Cache.
type keyFunc func(ctx context.Context, kid string) (*rsa.PublicKey, error)

func (f keyFunc) Key(ctx context.Context, kid string) (*rsa.PublicKey, error) { return f(ctx, kid) }

// publishedKeys knows only the primary key under synthKID, as the Cache does
// after loading a JWKS that contains it.
func publishedKeys() keySource {
	pub := &signers().primary.PublicKey
	return keyFunc(func(_ context.Context, kid string) (*rsa.PublicKey, error) {
		if kid == synthKID {
			return pub, nil
		}
		return nil, errKeyUnknown
	})
}

func synthPolicy() Policy {
	return Policy{
		AppID:         synthAppID,
		EnvironmentID: synthEnvID,
		CloudIDs:      []string{synthSiteA, synthSiteB},
		ClockSkew:     10 * time.Second,
	}
}

func newTestVerifier(keys keySource) *Verifier {
	v := NewVerifier(synthPolicy(), keys)
	v.now = func() time.Time { return synthNow }
	return v
}

func segment(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// signSegments signs already encoded header and payload parts exactly as
// given and returns the compact JWS.
func signSegments(t testing.TB, key *rsa.PrivateKey, h, p string) string {
	t.Helper()
	digest := sha256.Sum256([]byte(h + "." + p))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return h + "." + p + "." + segment(string(sig))
}

// signRaw signs raw header and payload JSON text, which may hold anything a
// JSON encoder would never produce.
func signRaw(t testing.TB, key *rsa.PrivateKey, header, payload string) string {
	t.Helper()
	return signSegments(t, key, segment(header), segment(payload))
}

// parts splits a compact JWS built by the helpers above.
func parts(t testing.TB, token string) (h, p, s string) {
	t.Helper()
	f := strings.Split(token, ".")
	if len(f) != 3 {
		t.Fatalf("token has %d parts", len(f))
	}
	return f[0], f[1], f[2]
}

// edit applies old/new replacement pairs to s. Each old must occur exactly
// once, so a case can never silently test the unchanged document.
func edit(t testing.TB, s string, pairs ...string) string {
	t.Helper()
	if len(pairs)%2 != 0 {
		t.Fatal("edit needs old/new pairs")
	}
	for i := 0; i < len(pairs); i += 2 {
		if n := strings.Count(s, pairs[i]); n != 1 {
			t.Fatalf("edit: %q occurs %d times", pairs[i], n)
		}
		s = strings.Replace(s, pairs[i], pairs[i+1], 1)
	}
	return s
}

// verifyToken runs v on a single "Bearer" Authorization field.
func verifyToken(t *testing.T, v *Verifier, token string) (Claims, error) {
	t.Helper()
	return v.Verify(t.Context(), []string{"Bearer " + token})
}

// checkResult fails t unless Verify refused with reason want or, when want
// is empty, accepted with claims.
func checkResult(t *testing.T, got Claims, err error, want Reason, claims Claims) {
	t.Helper()
	if want == "" {
		if err != nil || got != claims {
			t.Fatalf("Verify = %+v, %v; want %+v, nil", got, err, claims)
		}
		return
	}
	var fe *Error
	if !errors.As(err, &fe) || fe.Reason != want {
		t.Fatalf("Verify error = %v, want reason %q", err, want)
	}
	if got != (Claims{}) {
		t.Fatalf("refused token returned claims %+v", got)
	}
}

// payloadCase is a correctly signed token whose payload differs from the
// valid one by edits; want "" means accepted with validClaims.
type payloadCase struct {
	name  string
	edits []string
	want  Reason
}

func runPayloadCases(t *testing.T, cases []payloadCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := edit(t, validPayload, tc.edits...)
			requireEscape(t, tc.name, payload)
			token := signRaw(t, signers().primary, validHeader, payload)
			got, err := verifyToken(t, newTestVerifier(publishedKeys()), token)
			checkResult(t, got, err, tc.want, validClaims)
		})
	}
}

func TestVerifyAcceptsValidToken(t *testing.T) {
	token := signRaw(t, signers().primary, validHeader, validPayload)
	got, err := verifyToken(t, newTestVerifier(publishedKeys()), token)
	checkResult(t, got, err, "", validClaims)
}

func TestNewVerifierDefaults(t *testing.T) {
	p := synthPolicy()
	p.InstallationIDs = []string{synthInstallID}
	v := NewVerifier(p, publishedKeys())
	t.Run("site_fallback_disabled_in_production", func(t *testing.T) {
		if v.siteFallback {
			t.Fatal("NewVerifier enabled the site fallback before Phase 0 evidence")
		}
	})
	t.Run("policy_lists_copied", func(t *testing.T) {
		p.CloudIDs[0] = synthSiteX
		p.InstallationIDs[0] = "changed"
		if v.policy.CloudIDs[0] != synthSiteA || v.policy.InstallationIDs[0] != synthInstallID {
			t.Fatal("changing the caller's Policy changed the Verifier")
		}
	})
}

func TestVerifyAuthorizationField(t *testing.T) {
	token := signRaw(t, signers().primary, validHeader, validPayload)
	h, p, s := parts(t, token)
	cases := []struct {
		name   string
		values []string
		want   Reason
	}{
		{"scheme_lowercase_accepted", []string{"bearer " + token}, ""},
		{"scheme_uppercase_accepted", []string{"BEARER " + token}, ""},
		{"scheme_mixed_case_accepted", []string{"bEaReR " + token}, ""},
		{"no_field", nil, ReasonAuthorization},
		{"empty_field_list", []string{}, ReasonAuthorization},
		{"repeated_field", []string{"Bearer " + token, "Bearer " + token}, ReasonAuthorization},
		{"repeated_field_one_empty", []string{"Bearer " + token, ""}, ReasonAuthorization},
		{"empty_value", []string{""}, ReasonAuthorization},
		{"scheme_only", []string{"Bearer"}, ReasonAuthorization},
		{"scheme_and_space_only", []string{"Bearer "}, ReasonAuthorization},
		{"other_scheme", []string{"Basic " + token}, ReasonAuthorization},
		{"scheme_truncated", []string{"Beare " + token}, ReasonAuthorization},
		{"scheme_without_space", []string{"Bearer" + token}, ReasonAuthorization},
		{"scheme_with_colon", []string{"Bearer:" + token}, ReasonAuthorization},
		{"tab_separator", []string{"Bearer\t" + token}, ReasonAuthorization},
		{"two_spaces", []string{"Bearer  " + token}, ReasonAuthorization},
		{"leading_space", []string{" Bearer " + token}, ReasonAuthorization},
		{"trailing_space", []string{"Bearer " + token + " "}, ReasonAuthorization},
		{"comma_joined_credentials", []string{"Bearer " + token + ", Bearer " + token}, ReasonAuthorization},
		{"comma_without_space", []string{"Bearer " + token + "," + token}, ReasonAuthorization},
		{"crlf_inside_part", []string{"Bearer " + h + "\r\n." + p + "." + s}, ReasonAuthorization},
		{"space_inside_part", []string{"Bearer " + h + " ." + p + "." + s}, ReasonAuthorization},
		{"padding_character", []string{"Bearer " + h + "." + p + "." + s + "=="}, ReasonAuthorization},
		{"standard_base64_plus", []string{"Bearer " + h + "+." + p + "." + s}, ReasonAuthorization},
		{"standard_base64_slash", []string{"Bearer " + h + "/." + p + "." + s}, ReasonAuthorization},
		{"nul_byte", []string{"Bearer " + token + "\x00"}, ReasonAuthorization},
		{"non_ascii", []string{"Bearer " + token + "é"}, ReasonAuthorization},
		{"quoted_token", []string{`Bearer "` + token + `"`}, ReasonAuthorization},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := newTestVerifier(publishedKeys()).Verify(t.Context(), tc.values)
			checkResult(t, got, err, tc.want, validClaims)
		})
	}
}

func TestVerifyTokenFormat(t *testing.T) {
	key := signers().primary
	token := signRaw(t, key, validHeader, validPayload)
	h, p, s := parts(t, token)
	withHeader := func(header string) string { return signRaw(t, key, header, validPayload) }
	// Unpadded base64 is never 1 mod 4 long.
	badH, badS := h, s
	for len(badH)%4 != 1 {
		badH += "A"
	}
	for len(badS)%4 != 1 {
		badS = badS[:len(badS)-1]
	}
	cases := []struct {
		name  string
		token string
		want  Reason
	}{
		{"two_parts", h + "." + p, ReasonTokenFormat},
		{"four_parts", token + "." + s, ReasonTokenFormat},
		{"empty_header_part", "." + p + "." + s, ReasonTokenFormat},
		{"empty_payload_part", h + ".." + s, ReasonTokenFormat},
		{"empty_signature_part", h + "." + p + ".", ReasonTokenFormat},
		{"separators_only", "..", ReasonTokenFormat},
		{"header_impossible_base64_length", signSegments(t, key, badH, p), ReasonTokenFormat},
		{"signature_impossible_base64_length", h + "." + p + "." + badS, ReasonTokenFormat},
		{"header_not_json", withHeader(`alg=RS256`), ReasonTokenFormat},
		{"header_not_object", withHeader(`["RS256","` + synthKID + `"]`), ReasonTokenFormat},
		{"header_trailing_json", withHeader(validHeader + `{}`), ReasonTokenFormat},
		{"header_trailing_text", withHeader(validHeader + ` x`), ReasonTokenFormat},
		{"header_duplicate_alg", withHeader(`{"alg":"RS256","alg":"RS256","kid":"` + synthKID + `"}`), ReasonTokenFormat},
		{"header_duplicate_alg_escaped", withHeader(esc(`{"alg":"none","~u0061lg":"RS256","kid":"` + synthKID + `"}`)), ReasonTokenFormat},
		{"header_duplicate_kid", withHeader(`{"alg":"RS256","kid":"other","kid":"` + synthKID + `"}`), ReasonTokenFormat},
		{"header_invalid_utf8", withHeader("{\"alg\":\"RS256\",\"kid\":\"" + synthKID + "\",\"x\":\"\xff\"}"), ReasonTokenFormat},
		{"header_lone_surrogate", withHeader(`{"alg":"RS256","kid":"` + synthKID + `","x":"\ud800"}`), ReasonTokenFormat},
		{"header_whitespace_accepted", withHeader(" { \"alg\" : \"RS256\" ,\n\"kid\":\"" + synthKID + "\" } "), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Only a case named *_escaped reads the decoded header, so a part
			// that does not decode matters to no other case.
			header, _ := base64.RawURLEncoding.DecodeString(strings.Split(tc.token, ".")[0])
			requireEscape(t, tc.name, string(header))
			got, err := verifyToken(t, newTestVerifier(publishedKeys()), tc.token)
			checkResult(t, got, err, tc.want, validClaims)
		})
	}
}

// tokenOfLength returns a valid signed token of exactly n bytes, padded with
// an unknown claim. Unpadded base64 is never 1 mod 4 long, so it varies the
// header's trailing whitespace as well as the filler.
func tokenOfLength(t *testing.T, n int) string {
	t.Helper()
	enc := base64.RawURLEncoding
	sigLen := enc.EncodedLen(signers().primary.Size())
	for ws := range 3 {
		header := validHeader + strings.Repeat(" ", ws)
		for pad := 0; ; pad++ {
			payload := edit(t, validPayload, lastMember,
				`"principal":"synthetic-principal","filler":"`+strings.Repeat("x", pad)+`"}`)
			total := enc.EncodedLen(len(header)) + 1 + enc.EncodedLen(len(payload)) + 1 + sigLen
			if total == n {
				return signRaw(t, signers().primary, header, payload)
			}
			if total > n {
				break
			}
		}
	}
	t.Fatalf("no token of %d bytes", n)
	return ""
}

func TestVerifyTokenSizeLimit(t *testing.T) {
	v := newTestVerifier(publishedKeys())
	t.Run("token_at_limit_accepted", func(t *testing.T) {
		got, err := verifyToken(t, v, tokenOfLength(t, MaxTokenBytes))
		checkResult(t, got, err, "", validClaims)
	})
	t.Run("token_over_limit_rejected", func(t *testing.T) {
		got, err := verifyToken(t, v, tokenOfLength(t, MaxTokenBytes+1))
		checkResult(t, got, err, ReasonTokenFormat, Claims{})
	})
	t.Run("limit_is_8_KiB", func(t *testing.T) {
		if MaxTokenBytes != 8192 {
			t.Fatalf("MaxTokenBytes = %d, PLAN.md §4.4 says 8 KiB", MaxTokenBytes)
		}
	})
}

// nonCanonical sets an unused trailing bit of an unpadded base64url part, an
// encoding that a lenient decoder maps to the same bytes.
func nonCanonical(t *testing.T, part string) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	if len(part)%4 == 0 {
		t.Fatal("part has no unused bits")
	}
	last := strings.IndexByte(alphabet, part[len(part)-1])
	if last < 0 || last&1 != 0 {
		t.Fatal("part is not canonical")
	}
	return part[:len(part)-1] + string(alphabet[last|1])
}

// TestVerifyStrictBase64 signs each part's non-canonical spelling, so only
// strict decoding refuses it: a lenient decoder would yield the same header,
// payload and signature, and the token would verify.
func TestVerifyStrictBase64(t *testing.T) {
	key := signers().primary
	header, payload := validHeader, validPayload
	for len(header)%3 == 0 {
		header += " "
	}
	for len(payload)%3 == 0 {
		payload += " "
	}
	h, p := segment(header), segment(payload)
	v := newTestVerifier(publishedKeys())

	t.Run("canonical_parts_accepted", func(t *testing.T) {
		got, err := verifyToken(t, v, signSegments(t, key, h, p))
		checkResult(t, got, err, "", validClaims)
	})
	t.Run("non_canonical_header", func(t *testing.T) {
		got, err := verifyToken(t, v, signSegments(t, key, nonCanonical(t, h), p))
		checkResult(t, got, err, ReasonTokenFormat, Claims{})
	})
	t.Run("non_canonical_payload", func(t *testing.T) {
		got, err := verifyToken(t, v, signSegments(t, key, h, nonCanonical(t, p)))
		checkResult(t, got, err, ReasonPayload, Claims{})
	})
	t.Run("non_canonical_signature", func(t *testing.T) {
		hh, pp, s := parts(t, signSegments(t, key, h, p))
		got, err := verifyToken(t, v, hh+"."+pp+"."+nonCanonical(t, s))
		checkResult(t, got, err, ReasonTokenFormat, Claims{})
	})
}

func TestVerifyHeaderRules(t *testing.T) {
	kid := `"kid":"` + synthKID + `"`
	cases := []struct {
		name   string
		header string
		want   Reason
	}{
		{"unknown_members_accepted", `{"alg":"RS256",` + kid + `,"typ":"JWT","cty":"x","x-extra":{"a":[null]}}`, ""},
		{"alg_none", `{"alg":"none",` + kid + `}`, ReasonHeader},
		{"alg_hs256", `{"alg":"HS256",` + kid + `}`, ReasonHeader},
		{"alg_rs384", `{"alg":"RS384",` + kid + `}`, ReasonHeader},
		{"alg_ps256", `{"alg":"PS256",` + kid + `}`, ReasonHeader},
		{"alg_lowercase", `{"alg":"rs256",` + kid + `}`, ReasonHeader},
		{"alg_trailing_space", `{"alg":"RS256 ",` + kid + `}`, ReasonHeader},
		{"alg_empty", `{"alg":"",` + kid + `}`, ReasonHeader},
		{"alg_missing", `{` + kid + `}`, ReasonHeader},
		{"alg_null", `{"alg":null,` + kid + `}`, ReasonHeader},
		{"alg_number", `{"alg":256,` + kid + `}`, ReasonHeader},
		{"alg_array", `{"alg":["RS256"],` + kid + `}`, ReasonHeader},
		{"alg_name_case_variant", `{"ALG":"RS256",` + kid + `}`, ReasonHeader},
		{"kid_missing", `{"alg":"RS256"}`, ReasonHeader},
		{"kid_empty", `{"alg":"RS256","kid":""}`, ReasonHeader},
		{"kid_null", `{"alg":"RS256","kid":null}`, ReasonHeader},
		{"kid_number", `{"alg":"RS256","kid":1}`, ReasonHeader},
		{"kid_object", `{"alg":"RS256","kid":{"id":"` + synthKID + `"}}`, ReasonHeader},
		{"kid_name_case_variant", `{"alg":"RS256","KID":"` + synthKID + `"}`, ReasonHeader},
		{"crit", `{"alg":"RS256",` + kid + `,"crit":["exp"]}`, ReasonHeader},
		{"crit_null", `{"alg":"RS256",` + kid + `,"crit":null}`, ReasonHeader},
		{"crit_name_escaped", esc(`{"alg":"RS256",` + kid + `,"~u0063rit":["exp"]}`), ReasonHeader},
		{"jku_name_escaped", esc(`{"alg":"RS256",` + kid + `,"~u006aku":"https://example.invalid/jwks"}`), ReasonHeader},
		{"jku", `{"alg":"RS256",` + kid + `,"jku":"https://example.invalid/jwks"}`, ReasonHeader},
		{"jku_null", `{"alg":"RS256",` + kid + `,"jku":null}`, ReasonHeader},
		{"jwk", `{"alg":"RS256",` + kid + `,"jwk":{"kty":"RSA"}}`, ReasonHeader},
		{"jwk_null", `{"alg":"RS256",` + kid + `,"jwk":null}`, ReasonHeader},
		{"x5u", `{"alg":"RS256",` + kid + `,"x5u":"https://example.invalid/cert"}`, ReasonHeader},
		{"x5u_null", `{"alg":"RS256",` + kid + `,"x5u":null}`, ReasonHeader},
		{"x5c", `{"alg":"RS256",` + kid + `,"x5c":["AAAA"]}`, ReasonHeader},
		{"x5c_null", `{"alg":"RS256",` + kid + `,"x5c":null}`, ReasonHeader},
		{"zip", `{"alg":"RS256",` + kid + `,"zip":"DEF"}`, ReasonHeader},
		{"zip_null", `{"alg":"RS256",` + kid + `,"zip":null}`, ReasonHeader},
		{"b64", `{"alg":"RS256",` + kid + `,"b64":false}`, ReasonHeader},
		{"b64_null", `{"alg":"RS256",` + kid + `,"b64":null}`, ReasonHeader},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requireEscape(t, tc.name, tc.header)
			token := signRaw(t, signers().primary, tc.header, validPayload)
			got, err := verifyToken(t, newTestVerifier(publishedKeys()), token)
			checkResult(t, got, err, tc.want, validClaims)
		})
	}
}

// TestVerifyRejectsHS256WithPublicKeyAsSecret is the classic algorithm
// confusion attack: an HMAC keyed with the published RSA key, which a
// verifier that let the header choose the algorithm would accept.
func TestVerifyRejectsHS256WithPublicKeyAsSecret(t *testing.T) {
	pub := &signers().primary.PublicKey
	pkix, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	secrets := map[string][]byte{
		"pkix_der":  pkix,
		"pkix_pem":  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix}),
		"pkcs1_der": x509.MarshalPKCS1PublicKey(pub),
		"pkcs1_pem": pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(pub)}),
	}
	headers := map[string]struct {
		header string
		want   Reason
	}{
		"hs256_header": {`{"alg":"HS256","kid":"` + synthKID + `"}`, ReasonHeader},
		"rs256_header": {validHeader, ReasonSignature},
	}
	for sname, secret := range secrets {
		for hname, hc := range headers {
			t.Run(hname+"_"+sname, func(t *testing.T) {
				h, p := segment(hc.header), segment(validPayload)
				mac := hmac.New(sha256.New, secret)
				mac.Write([]byte(h + "." + p))
				token := h + "." + p + "." + segment(string(mac.Sum(nil)))
				got, err := verifyToken(t, newTestVerifier(publishedKeys()), token)
				checkResult(t, got, err, hc.want, Claims{})
			})
		}
	}
}

func TestVerifyRejectsAlgNone(t *testing.T) {
	p := segment(validPayload)
	cases := []struct {
		name  string
		token string
		want  Reason
	}{
		{"unsigned", segment(`{"alg":"none"}`) + "." + p + ".", ReasonTokenFormat},
		{"unsigned_with_kid", segment(`{"alg":"none","kid":"`+synthKID+`"}`) + "." + p + ".", ReasonTokenFormat},
		{"with_signature", signRaw(t, signers().primary, `{"alg":"none","kid":"`+synthKID+`"}`, validPayload), ReasonHeader},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := verifyToken(t, newTestVerifier(publishedKeys()), tc.token)
			checkResult(t, got, err, tc.want, Claims{})
		})
	}
}

func TestVerifyKeyLookup(t *testing.T) {
	token := signRaw(t, signers().primary, validHeader, validPayload)
	pub := &signers().primary.PublicKey
	failing := func(err error) keySource {
		return keyFunc(func(context.Context, string) (*rsa.PublicKey, error) { return nil, err })
	}

	t.Run("unknown_kid", func(t *testing.T) {
		header := `{"alg":"RS256","kid":"synthetic-key-2"}`
		got, err := verifyToken(t, newTestVerifier(publishedKeys()), signRaw(t, signers().primary, header, validPayload))
		checkResult(t, got, err, ReasonKeyUnknown, Claims{})
	})
	t.Run("lookup_error_is_unknown_key", func(t *testing.T) {
		got, err := verifyToken(t, newTestVerifier(failing(errors.New("synthetic failure"))), token)
		checkResult(t, got, err, ReasonKeyUnknown, Claims{})
	})
	t.Run("nil_key_is_unknown_key", func(t *testing.T) {
		got, err := verifyToken(t, newTestVerifier(failing(nil)), token)
		checkResult(t, got, err, ReasonKeyUnknown, Claims{})
	})
	t.Run("not_ready_is_not_a_rejection", func(t *testing.T) {
		for _, keyErr := range []error{ErrNotReady, fmt.Errorf("cache: %w", ErrNotReady)} {
			got, err := verifyToken(t, newTestVerifier(failing(keyErr)), token)
			var fe *Error
			if err != ErrNotReady || errors.As(err, &fe) || got != (Claims{}) {
				t.Fatalf("Verify = %+v, %v; want ErrNotReady itself", got, err)
			}
		}
	})
	t.Run("lookup_receives_request_context", func(t *testing.T) {
		type ctxKey struct{}
		ctx := context.WithValue(t.Context(), ctxKey{}, "request")
		var seen any
		keys := keyFunc(func(c context.Context, _ string) (*rsa.PublicKey, error) {
			seen = c.Value(ctxKey{})
			return pub, nil
		})
		if _, err := newTestVerifier(keys).Verify(ctx, []string{"Bearer " + token}); err != nil {
			t.Fatal(err)
		}
		if seen != "request" {
			t.Fatal("the key lookup did not get the request context, so caller cancellation cannot end an unknown-key wait")
		}
	})
	t.Run("malformed_token_never_looks_up_a_key", func(t *testing.T) {
		called := false
		keys := keyFunc(func(context.Context, string) (*rsa.PublicKey, error) {
			called = true
			return pub, nil
		})
		v := newTestVerifier(keys)
		for _, bad := range []string{"x.y", segment(`{"alg":"HS256","kid":"k"}`) + ".e30.AAAA"} {
			if _, err := verifyToken(t, v, bad); err == nil {
				t.Fatal("malformed token accepted")
			}
		}
		if called {
			t.Fatal("a malformed token reached the key cache, where an unknown kid triggers a refresh")
		}
	})
}

func TestVerifySignature(t *testing.T) {
	key := signers().primary
	token := signRaw(t, key, validHeader, validPayload)
	h, p, s := parts(t, token)
	_, _, otherSig := parts(t, signRaw(t, key, validHeader, edit(t, validPayload, `"synthetic-jti"`, `"synthetic-jti-2"`)))
	sig, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		token string
		want  Reason
	}{
		{"same_kid_different_key", signRaw(t, signers().other, validHeader, validPayload), ReasonSignature},
		{"tampered_payload", h + "." + segment(edit(t, validPayload, `"synthetic-principal"`, `"tampered-principal"`)) + "." + s, ReasonSignature},
		{"tampered_header", segment(`{"alg":"RS256","kid":"`+synthKID+`","typ":"jwt"}`) + "." + p + "." + s, ReasonSignature},
		{"signature_of_another_token", h + "." + p + "." + otherSig, ReasonSignature},
		{"truncated_signature", h + "." + p + "." + segment(string(sig[:len(sig)-1])), ReasonSignature},
		{"extended_signature", h + "." + p + "." + segment(string(sig)+"\x00"), ReasonSignature},
		{"signature_with_leading_zero", h + "." + p + "." + segment("\x00"+string(sig)), ReasonSignature},
		{"zero_signature", h + "." + p + "." + segment(string(make([]byte, key.Size()))), ReasonSignature},
		{"signature_checked_before_payload", signRaw(t, signers().other, validHeader, "not json"), ReasonSignature},
		{"payload_checked_after_signature", signRaw(t, key, validHeader, "not json"), ReasonPayload},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := verifyToken(t, newTestVerifier(publishedKeys()), tc.token)
			checkResult(t, got, err, tc.want, Claims{})
		})
	}
}

func TestVerifyPayloadJSON(t *testing.T) {
	principal := `"synthetic-principal"`
	extra := func(member string) []string {
		return []string{lastMember, `"principal":"synthetic-principal",` + member + `}`}
	}
	nested := func(depth int) string { return strings.Repeat("[", depth) + strings.Repeat("]", depth) }
	runPayloadCases(t, []payloadCase{
		{"not_json", []string{validPayload, "not json"}, ReasonPayload},
		{"not_an_object", []string{validPayload, "[" + validPayload + "]"}, ReasonPayload},
		{"trailing_object", []string{lastMember, lastMember + "{}"}, ReasonPayload},
		{"trailing_text", []string{lastMember, lastMember + " x"}, ReasonPayload},
		{"trailing_whitespace_accepted", []string{lastMember, lastMember + " \r\n\t"}, ""},
		{"invalid_utf8_in_value", []string{principal, "\"\xff\""}, ReasonPayload},
		{"invalid_utf8_in_name", []string{`"principal"`, "\"pr\xffincipal\""}, ReasonPayload},
		{"overlong_utf8", []string{principal, "\"\xc0\xaf\""}, ReasonPayload},
		{"utf8_encoded_surrogate", []string{principal, "\"\xed\xa0\x80\""}, ReasonPayload},
		{"truncated_utf8", []string{principal, "\"\xe2\x82\""}, ReasonPayload},
		{"lone_high_surrogate", []string{principal, `"\ud800"`}, ReasonPayload},
		{"lone_low_surrogate", []string{principal, `"\udc00"`}, ReasonPayload},
		{"reversed_surrogates", []string{principal, `"\udc00\ud800"`}, ReasonPayload},
		{"high_surrogate_then_text", []string{principal, `"\ud800x"`}, ReasonPayload},
		{"two_high_surrogates", []string{principal, `"\ud800\ud800"`}, ReasonPayload},
		{"lone_surrogate_in_name", []string{`"principal"`, `"\ud800"`}, ReasonPayload},
		{"surrogate_pair_escaped_accepted", []string{principal, esc(`"~ud83d~ude00"`)}, ""},
		{"utf8_text_accepted", []string{principal, `"tööline 😀"`}, ""},
		{"duplicate_top_level", []string{issMember, issMember + issMember}, ReasonPayload},
		{"duplicate_top_level_escaped", []string{issMember, issMember + esc(`"~u0069ss":"forge/invocation-token",`)}, ReasonPayload},
		{"duplicate_top_level_last_valid", []string{issMember, `"iss":"forge/other",` + issMember}, ReasonPayload},
		{"duplicate_app", []string{appMember, appMember + appMember}, ReasonPayload},
		{"duplicate_in_app", []string{installIDMember, installIDMember + installIDMember}, ReasonPayload},
		{"duplicate_in_app_escaped", []string{installIDMember, installIDMember + esc(`"~u0069nstallationId":"`+synthInstallID+`",`)}, ReasonPayload},
		{"duplicate_in_app_environment", []string{envMember, `"environment":{"id":"other","id":"` + synthEnvID + `"},`}, ReasonPayload},
		{"duplicate_in_app_environment_escaped", []string{envMember, esc(`"environment":{"id":"other","~u0069d":"` + synthEnvID + `"},`)}, ReasonPayload},
		{"duplicate_in_context", []string{contextMember, `"context":{"cloudId":"` + synthSiteX + `","cloudId":"` + synthSiteA + `"},`}, ReasonPayload},
		{"duplicate_in_context_escaped", []string{contextMember, esc(`"context":{"cloudId":"` + synthSiteX + `","~u0063loudId":"` + synthSiteA + `"},`)}, ReasonPayload},
		{"duplicate_in_installation_context", []string{installationMember, `"installation":{"contexts":[{"cloudId":"` + synthSiteX + `","cloudId":"` + synthSiteA + `"}]},`}, ReasonPayload},
		{"duplicate_in_installation_context_escaped", []string{installationMember, esc(`"installation":{"contexts":[{"cloudId":"` + synthSiteX + `","~u0063loudId":"` + synthSiteA + `"}]},`)}, ReasonPayload},
		{"duplicate_in_unknown_claim", extra(`"future":{"a":1,"a":1}`), ReasonPayload},
		{"nesting_at_limit_accepted", extra(`"deep":` + nested(maxJSONDepth-1)), ""},
		{"nesting_over_limit", extra(`"deep":` + nested(maxJSONDepth)), ReasonPayload},
	})
}

func TestVerifyClaims(t *testing.T) {
	extra := func(member string) []string {
		return []string{lastMember, `"principal":"synthetic-principal",` + member + `}`}
	}
	aud := func(raw string) []string { return []string{audMember, `"aud":` + raw + `,`} }
	exp := func(raw string) []string { return []string{expMember, `"exp":` + raw + `,`} }
	nbf := func(raw string) []string { return []string{nbfMember, `"nbf":` + raw + `,`} }
	env := func(raw string) []string { return []string{envMember, `"environment":` + raw + `,`} }
	app := func(raw string) []string { return []string{appMember, `"app":` + raw + `,`} }
	const otherApp = `"ari:cloud:ecosystem::app/00000000-0000-4000-8000-0000000000ff"`
	runPayloadCases(t, []payloadCase{
		{"icLabel_string", extra(`"icLabel":"synthetic"`), ReasonIsolatedCloud},
		{"icLabel_null", extra(`"icLabel":null`), ReasonIsolatedCloud},
		{"icLabel_object", extra(`"icLabel":{}`), ReasonIsolatedCloud},

		{"iss_escaped_solidus_accepted", []string{issMember, `"iss":"forge\/invocation-token",`}, ""},
		{"iss_value_escaped_accepted", []string{issMember, esc(`"iss":"forge~u002finvocation-token",`)}, ""},
		{"iss_name_escaped_accepted", []string{issMember, esc(`"~u0069ss":"forge/invocation-token",`)}, ""},
		{"iss_missing", []string{issMember, ""}, ReasonIssuer},
		{"iss_null", []string{issMember, `"iss":null,`}, ReasonIssuer},
		{"iss_number", []string{issMember, `"iss":1,`}, ReasonIssuer},
		{"iss_array", []string{issMember, `"iss":["forge/invocation-token"],`}, ReasonIssuer},
		{"iss_other", []string{issMember, `"iss":"forge/invocation-tokens",`}, ReasonIssuer},
		{"iss_case_differs", []string{issMember, `"iss":"Forge/Invocation-Token",`}, ReasonIssuer},
		{"iss_trailing_space", []string{issMember, `"iss":"forge/invocation-token ",`}, ReasonIssuer},
		{"iss_name_case_variant", []string{issMember, `"ISS":"forge/invocation-token",`}, ReasonIssuer},

		{"aud_array_accepted", aud(`["` + synthAppID + `"]`), ""},
		{"aud_array_with_other_apps_accepted", aud(`[` + otherApp + `,"` + synthAppID + `"]`), ""},
		{"aud_missing", []string{audMember, ""}, ReasonAudience},
		{"aud_null", aud(`null`), ReasonAudience},
		{"aud_number", aud(`1`), ReasonAudience},
		{"aud_object", aud(`{"aud":"` + synthAppID + `"}`), ReasonAudience},
		{"aud_other_app", aud(otherApp), ReasonAudience},
		{"aud_case_differs", aud(`"` + strings.ToUpper(synthAppID) + `"`), ReasonAudience},
		{"aud_empty_string", aud(`""`), ReasonAudience},
		{"aud_empty_array", aud(`[]`), ReasonAudience},
		{"aud_array_without_app", aud(`[` + otherApp + `]`), ReasonAudience},
		{"aud_array_with_empty_string", aud(`["","` + synthAppID + `"]`), ReasonAudience},
		{"aud_array_with_number", aud(`[1,"` + synthAppID + `"]`), ReasonAudience},
		{"aud_array_with_null", aud(`[null,"` + synthAppID + `"]`), ReasonAudience},
		{"aud_nested_array", aud(`[["` + synthAppID + `"]]`), ReasonAudience},
		{"aud_name_case_variant", []string{audMember, `"Aud":"` + synthAppID + `",`}, ReasonAudience},

		{"exp_fractional_accepted", exp(`1800000020.75`), ""},
		{"exp_exponent_form_accepted", exp(`1.80000002E9`), ""},
		{"exp_at_max_accepted", exp(`253402300799`), ""},
		{"nbf_zero_accepted", nbf(`0`), ""},
		{"dates_surrounded_by_whitespace_accepted", []string{expMember, "\"exp\" :\n1800000020 ,", nbfMember, "\"nbf\":\t1799999995\t,"}, ""},
		{"exp_missing", []string{expMember, ""}, ReasonDates},
		{"nbf_missing", []string{nbfMember, ""}, ReasonDates},
		{"exp_null", exp(`null`), ReasonDates},
		{"nbf_null", nbf(`null`), ReasonDates},
		{"exp_string", exp(`"1800000020"`), ReasonDates},
		{"nbf_string", nbf(`"1799999995"`), ReasonDates},
		{"exp_bool", exp(`true`), ReasonDates},
		{"exp_object", exp(`{}`), ReasonDates},
		{"exp_array", exp(`[1800000020]`), ReasonDates},
		{"nbf_negative", nbf(`-1`), ReasonDates},
		{"nbf_negative_zero", nbf(`-0`), ReasonDates},
		{"exp_above_max", exp(`253402300800`), ReasonDates},
		{"exp_max_plus_fraction", exp(`253402300799.5`), ReasonDates},
		{"exp_huge_exponent", exp(`1e999999999`), ReasonDates},
		{"nbf_huge_exponent", nbf(`1E+999999999999999999999`), ReasonDates},
		{"exp_equal_nbf", exp(`1799999995`), ReasonDates},
		{"exp_before_nbf", exp(`1799999994`), ReasonDates},
		{"expired", append(exp(`1799999990`), nbf(`1799999980`)...), ReasonExpired},
		{"not_yet_valid", nbf(`1800000011`), ReasonNotYetValid},
		{"exp_name_case_variant", []string{expMember, `"EXP":1800000020,`}, ReasonDates},

		{"app_missing", []string{appMember, ""}, ReasonPayload},
		{"app_null", app(`null`), ReasonPayload},
		{"app_string", app(`"` + synthAppID + `"`), ReasonPayload},
		{"app_array", app(`[{}]`), ReasonPayload},
		{"app_name_case_variant", []string{`"app":{`, `"App":{`}, ReasonPayload},

		{"environment_id_value_escaped_accepted", env(esc(`{"id":"` + strings.TrimSuffix(synthEnvID, "2") + `~u0032"}`)), ""},
		{"environment_missing", []string{envMember, ""}, ReasonEnvironment},
		{"environment_null", env(`null`), ReasonEnvironment},
		{"environment_string", env(`"` + synthEnvID + `"`), ReasonEnvironment},
		{"environment_array", env(`[{"id":"` + synthEnvID + `"}]`), ReasonEnvironment},
		{"environment_id_missing", env(`{"type":"DEVELOPMENT"}`), ReasonEnvironment},
		{"environment_id_null", env(`{"id":null}`), ReasonEnvironment},
		{"environment_id_number", env(`{"id":2}`), ReasonEnvironment},
		{"environment_id_empty", env(`{"id":""}`), ReasonEnvironment},
		{"environment_id_other", env(`{"id":"00000000-0000-4000-8000-0000000000ff"}`), ReasonEnvironment},
		{"environment_id_name_case_variant", env(`{"ID":"` + synthEnvID + `"}`), ReasonEnvironment},
		{"environment_name_case_variant", []string{envMember, `"Environment":{"id":"` + synthEnvID + `"},`}, ReasonEnvironment},

		{"unknown_claims_accepted", extra(`"future":{"nested":[1,null,{"x":true}]},"empty":null`), ""},
		{"unknown_app_members_accepted", []string{appIDMember, `"id":"` + synthAppID + `","apiBaseUrl":"https://example.invalid","module":{"key":"k"}}`}, ""},
		{"unknown_context_members_accepted", []string{`"moduleKey":"token-relay"`, `"moduleKey":"token-relay","extension":{"type":"x"}`}, ""},
		{"unknown_installation_context_members_accepted", []string{installationMember, `"installation":{"id":"x","contexts":[{"cloudId":"` + synthSiteA + `","product":"jira"}]},`}, ""},
		// The case variants hold values that would fail if they were matched
		// to the real claims, so acceptance proves names are not folded.
		{"case_variant_names_are_distinct_claims", extra(`"ISS":"x","Aud":"x","EXP":"x","App":null,"CONTEXT":{"cloudId":"` + synthSiteX + `"},"IcLabel":"x"`), ""},
		{"case_variant_names_in_app_are_distinct", []string{appIDMember, `"id":"` + synthAppID + `","Environment":null,"InstallationId":null,"Installation":"x"}`}, ""},
		{"case_variant_names_in_context_are_distinct", []string{`"moduleKey":"token-relay"`, `"moduleKey":"token-relay","CloudId":"` + synthSiteX + `"`}, ""},
	})
}

func TestVerifyClockSkewBoundaries(t *testing.T) {
	at := time.Unix
	cases := []struct {
		name     string
		exp, nbf string
		skew     time.Duration
		now      time.Time
		want     Reason
	}{
		{"now_at_exp_plus_skew_rejected", "1800000020", "1799999995", 10 * time.Second, at(1800000030, 0), ReasonExpired},
		{"now_just_before_exp_plus_skew_accepted", "1800000020", "1799999995", 10 * time.Second, at(1800000029, 999999999), ""},
		{"now_plus_skew_at_nbf_accepted", "1800000020", "1800000010", 10 * time.Second, at(1800000000, 0), ""},
		{"now_plus_skew_just_before_nbf_rejected", "1800000020", "1800000010", 10 * time.Second, at(1799999999, 999999999), ReasonNotYetValid},
		{"zero_skew_now_at_exp_rejected", "1800000020", "1800000000", 0, at(1800000020, 0), ReasonExpired},
		{"zero_skew_now_at_nbf_accepted", "1800000020", "1800000000", 0, at(1800000000, 0), ""},
		{"fractional_exp_boundary_rejected", "1800000020.5", "1799999995", 10 * time.Second, at(1800000030, 500000000), ReasonExpired},
		{"fractional_exp_just_inside_accepted", "1800000020.5", "1799999995", 10 * time.Second, at(1800000030, 499999999), ""},
		{"sub_nanosecond_exp_rounds_down", "1800000020.0000000009", "1799999995", 10 * time.Second, at(1800000030, 0), ReasonExpired},
		{"sub_nanosecond_nbf_rounds_up", "1800000020", "1800000010.0000000001", 10 * time.Second, at(1800000000, 0), ReasonNotYetValid},
		{"sub_nanosecond_nbf_rounded_up_accepted", "1800000020", "1800000010.0000000001", 10 * time.Second, at(1800000000, 1), ""},
		{"exponent_exp_boundary_rejected", "1.80000002e9", "1799999995", 10 * time.Second, at(1800000030, 0), ReasonExpired},
		{"exponent_exp_just_inside_accepted", "18000000200E-1", "1799999995", 10 * time.Second, at(1800000029, 999999999), ""},
		{"exp_equal_nbf_fractional_rejected", "1800000000.5", "1800000000.5", 10 * time.Second, at(1800000000, 0), ReasonDates},
		{"exp_one_nanosecond_after_nbf_accepted", "1800000000.000000001", "1800000000", 10 * time.Second, at(1800000000, 0), ""},
		{"sub_nanosecond_validity_rejected", "1800000000.0000000002", "1800000000.0000000001", 10 * time.Second, at(1800000000, 0), ReasonDates},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := edit(t, validPayload, expMember, `"exp":`+tc.exp+`,`, nbfMember, `"nbf":`+tc.nbf+`,`)
			v := newTestVerifier(publishedKeys())
			v.policy.ClockSkew = tc.skew
			v.now = func() time.Time { return tc.now }
			got, err := verifyToken(t, v, signRaw(t, signers().primary, validHeader, payload))
			checkResult(t, got, err, tc.want, validClaims)
		})
	}
}

// TestVerifyChecksClaimsInOrder breaks every claim, then repairs them one at
// a time. It pins check()'s fixed order, which decides the logged
// auth_reason when several claims fail.
func TestVerifyChecksClaimsInOrder(t *testing.T) {
	steps := []struct {
		want      Reason
		good, bad string
	}{
		{ReasonIsolatedCloud, lastMember, `"principal":"synthetic-principal","icLabel":"x"}`},
		{ReasonIssuer, issMember, `"iss":"x",`},
		{ReasonAudience, audMember, `"aud":"x",`},
		{ReasonDates, expMember, `"exp":"x",`},
		{ReasonPayload, `"app":{`, `"App":{`},
		{ReasonEnvironment, envMember, `"environment":null,`},
		{ReasonInstallation, installIDMember, `"installationId":null,`},
		{ReasonCloudID, contextMember, `"context":{"cloudId":"` + synthSiteX + `"},`},
	}
	payload := validPayload
	for _, s := range steps {
		payload = edit(t, payload, s.good, s.bad)
	}
	v := newTestVerifier(publishedKeys())
	for _, s := range steps {
		got, err := verifyToken(t, v, signRaw(t, signers().primary, validHeader, payload))
		checkResult(t, got, err, s.want, Claims{})
		payload = edit(t, payload, s.bad, s.good)
	}
	got, err := verifyToken(t, v, signRaw(t, signers().primary, validHeader, payload))
	checkResult(t, got, err, "", validClaims)
}

func TestVerifyInstallationPin(t *testing.T) {
	const otherInstall = "ari:cloud:ecosystem::installation/00000000-0000-4000-8000-0000000000ff"
	member := func(raw string) string { return `"installationId":` + raw + `,` }
	cases := []struct {
		name   string
		pin    []string
		member string // replaces installIDMember; "" removes it
		want   Reason
	}{
		{"no_pin_absent_accepted", nil, "", ""},
		{"no_pin_present_accepted", nil, installIDMember, ""},
		{"no_pin_null_rejected", nil, member(`null`), ReasonInstallation},
		{"no_pin_empty_rejected", nil, member(`""`), ReasonInstallation},
		{"no_pin_number_rejected", nil, member(`3`), ReasonInstallation},
		{"no_pin_object_rejected", nil, member(`{"id":"x"}`), ReasonInstallation},
		{"pin_listed_accepted", []string{otherInstall, synthInstallID}, installIDMember, ""},
		{"pin_not_listed_rejected", []string{otherInstall}, installIDMember, ReasonInstallation},
		{"pin_absent_rejected", []string{synthInstallID}, "", ReasonInstallation},
		{"pin_null_rejected", []string{synthInstallID}, member(`null`), ReasonInstallation},
		{"pin_case_differs_rejected", []string{synthInstallID}, member(`"` + strings.ToUpper(synthInstallID) + `"`), ReasonInstallation},
		{"pin_name_case_variant_rejected", []string{synthInstallID}, `"InstallationId":"` + synthInstallID + `",`, ReasonInstallation},
		{"empty_pin_entry_never_matches_absent_id", []string{""}, "", ReasonInstallation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := edit(t, validPayload, installIDMember, tc.member)
			p := synthPolicy()
			p.InstallationIDs = tc.pin
			v := NewVerifier(p, publishedKeys())
			v.now = func() time.Time { return synthNow }
			got, err := verifyToken(t, v, signRaw(t, signers().primary, validHeader, payload))
			checkResult(t, got, err, tc.want, validClaims)
		})
	}
}

func TestVerifySitePin(t *testing.T) {
	site := func(id string) string { return `{"cloudId":"` + id + `"}` }
	contexts := func(entries ...string) string { return `{"contexts":[` + strings.Join(entries, ",") + `]}` }
	inv := func(raw string) string { return `"context":` + raw + `,` }
	inst := func(raw string) string { return `"installation":` + raw + `,` }
	const absent = ""
	cases := []struct {
		name         string
		context      string // replaces contextMember; absent removes it
		installation string // replaces installationMember; absent removes it
		fallback     bool
		want         Reason
		site         string
	}{
		{"allowed_invocation_site", inv(site(synthSiteA)), inst(contexts(site(synthSiteA))), false, "", synthSiteA},
		{"second_allowed_invocation_site", inv(site(synthSiteB)), inst(contexts(site(synthSiteB))), false, "", synthSiteB},
		{"invocation_site_without_installation", inv(site(synthSiteA)), absent, false, "", synthSiteA},
		{"invocation_site_with_empty_contexts", inv(site(synthSiteA)), inst(contexts()), false, "", synthSiteA},
		{"invocation_site_among_installation_sites", inv(site(synthSiteA)), inst(contexts(site(synthSiteB), site(synthSiteA))), false, "", synthSiteA},
		{"invocation_site_with_contexts_without_sites", inv(site(synthSiteA)), inst(contexts(`{}`)), false, "", synthSiteA},
		{"invocation_site_decides_with_fallback_enabled", inv(site(synthSiteB)), inst(contexts(site(synthSiteB))), true, "", synthSiteB},
		// An escaped spelling of the allowed site is the same string once
		// decoded, so a parser that refused escapes would fail this case.
		{"invocation_site_value_escaped_accepted", inv(site(esc(strings.TrimSuffix(synthSiteA, "a") + "~u0061"))), inst(contexts(site(synthSiteA))), false, "", synthSiteA},
		{"installation_site_value_escaped_accepted", inv(site(synthSiteA)), inst(contexts(site(esc("~u0030" + synthSiteA[1:])))), false, "", synthSiteA},

		{"disallowed_invocation_site", inv(site(synthSiteX)), inst(contexts(site(synthSiteX))), false, ReasonCloudID, ""},
		{"disallowed_invocation_site_without_installation", inv(site(synthSiteX)), absent, false, ReasonCloudID, ""},
		{"invocation_site_null", inv(`{"cloudId":null}`), inst(contexts(site(synthSiteA))), false, ReasonCloudID, ""},
		{"invocation_site_empty", inv(`{"cloudId":""}`), inst(contexts(site(synthSiteA))), false, ReasonCloudID, ""},
		{"invocation_site_number", inv(`{"cloudId":10}`), inst(contexts(site(synthSiteA))), false, ReasonCloudID, ""},
		{"invocation_site_array", inv(`{"cloudId":["` + synthSiteA + `"]}`), inst(contexts(site(synthSiteA))), false, ReasonCloudID, ""},
		{"invocation_site_case_differs", inv(site(strings.ToUpper(synthSiteA))), absent, false, ReasonCloudID, ""},
		{"context_null", inv(`null`), inst(contexts(site(synthSiteA))), false, ReasonCloudID, ""},
		{"context_string", inv(`"` + synthSiteA + `"`), inst(contexts(site(synthSiteA))), false, ReasonCloudID, ""},
		{"context_array", inv(`[` + site(synthSiteA) + `]`), inst(contexts(site(synthSiteA))), false, ReasonCloudID, ""},

		{"mismatch_does_not_fall_back", inv(site(synthSiteX)), inst(contexts(site(synthSiteA))), false, ReasonCloudID, ""},
		{"mismatch_does_not_fall_back_with_fallback_enabled", inv(site(synthSiteX)), inst(contexts(site(synthSiteA))), true, ReasonCloudID, ""},
		{"conflicting_sources", inv(site(synthSiteA)), inst(contexts(site(synthSiteB))), false, ReasonCloudID, ""},
		{"conflicting_sources_with_fallback_enabled", inv(site(synthSiteA)), inst(contexts(site(synthSiteB))), true, ReasonCloudID, ""},
		{"null_invocation_site_does_not_fall_back", inv(`{"cloudId":null}`), inst(contexts(site(synthSiteA))), true, ReasonCloudID, ""},

		{"installation_null", inv(site(synthSiteA)), inst(`null`), false, ReasonCloudID, ""},
		{"installation_string", inv(site(synthSiteA)), inst(`"x"`), false, ReasonCloudID, ""},
		{"installation_array", inv(site(synthSiteA)), inst(`[` + site(synthSiteA) + `]`), false, ReasonCloudID, ""},
		{"contexts_null", inv(site(synthSiteA)), inst(`{"contexts":null}`), false, ReasonCloudID, ""},
		{"contexts_object", inv(site(synthSiteA)), inst(`{"contexts":` + site(synthSiteA) + `}`), false, ReasonCloudID, ""},
		{"context_entry_null", inv(site(synthSiteA)), inst(contexts(`null`)), false, ReasonCloudID, ""},
		{"context_entry_string", inv(site(synthSiteA)), inst(contexts(`"` + synthSiteA + `"`)), false, ReasonCloudID, ""},
		{"context_entry_site_null", inv(site(synthSiteA)), inst(contexts(`{"cloudId":null}`)), false, ReasonCloudID, ""},
		{"context_entry_site_empty", inv(site(synthSiteA)), inst(contexts(`{"cloudId":""}`)), false, ReasonCloudID, ""},
		{"context_entry_site_empty_beside_invocation_site", inv(site(synthSiteA)), inst(contexts(site(synthSiteA), `{"cloudId":""}`)), false, ReasonCloudID, ""},
		{"context_entry_site_null_beside_invocation_site", inv(site(synthSiteA)), inst(contexts(site(synthSiteA), `{"cloudId":null}`)), false, ReasonCloudID, ""},
		{"context_entry_site_number", inv(site(synthSiteA)), inst(contexts(`{"cloudId":1}`)), false, ReasonCloudID, ""},

		{"missing_site_rejected_without_fallback", absent, inst(contexts(site(synthSiteA))), false, ReasonCloudID, ""},
		{"context_without_site_rejected_without_fallback", inv(`{"moduleKey":"token-relay"}`), inst(contexts(site(synthSiteA))), false, ReasonCloudID, ""},
		{"context_name_case_variant", `"CONTEXT":` + site(synthSiteA) + `,`, inst(contexts(site(synthSiteA))), false, ReasonCloudID, ""},
		{"cloudId_name_case_variant", inv(`{"CloudId":"` + synthSiteA + `"}`), inst(contexts(site(synthSiteA))), false, ReasonCloudID, ""},
		{"no_site_anywhere", absent, absent, false, ReasonCloudID, ""},

		{"fallback_single_site", absent, inst(contexts(site(synthSiteA))), true, "", synthSiteA},
		{"fallback_repeated_single_site", absent, inst(contexts(site(synthSiteB), site(synthSiteB))), true, "", synthSiteB},
		{"fallback_context_without_site", inv(`{"moduleKey":"token-relay"}`), inst(contexts(site(synthSiteA))), true, "", synthSiteA},
		{"fallback_zero_contexts", absent, inst(contexts()), true, ReasonCloudID, ""},
		{"fallback_contexts_absent", absent, inst(`{}`), true, ReasonCloudID, ""},
		{"fallback_installation_absent", absent, absent, true, ReasonCloudID, ""},
		{"fallback_two_distinct_allowed_sites", absent, inst(contexts(site(synthSiteA), site(synthSiteB))), true, ReasonCloudID, ""},
		{"fallback_entry_without_site", absent, inst(contexts(site(synthSiteA), `{}`)), true, ReasonCloudID, ""},
		{"fallback_only_entries_without_site", absent, inst(contexts(`{}`)), true, ReasonCloudID, ""},
		{"fallback_malformed_entry", absent, inst(contexts(site(synthSiteA), `null`)), true, ReasonCloudID, ""},
		{"fallback_malformed_site", absent, inst(contexts(site(synthSiteA), `{"cloudId":""}`)), true, ReasonCloudID, ""},
		{"fallback_disallowed_site", absent, inst(contexts(site(synthSiteX))), true, ReasonCloudID, ""},
		{"fallback_case_variant_entry_name", absent, inst(contexts(`{"CloudId":"` + synthSiteA + `"}`)), true, ReasonCloudID, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := edit(t, validPayload, contextMember, tc.context, installationMember, tc.installation)
			requireEscape(t, tc.name, payload)
			v := newTestVerifier(publishedKeys())
			v.siteFallback = tc.fallback
			got, err := verifyToken(t, v, signRaw(t, signers().primary, validHeader, payload))
			checkResult(t, got, err, tc.want, Claims{CloudID: tc.site})
		})
	}
}

// TestVerifySiteOnlyFromPayload shows that a site outside the signed
// payload's claims, here in the JWS header, is never used (PLAN.md §4.4).
func TestVerifySiteOnlyFromPayload(t *testing.T) {
	header := `{"alg":"RS256","kid":"` + synthKID + `","context":{"cloudId":"` + synthSiteA + `"},"cloudId":"` + synthSiteA + `"}`
	payload := edit(t, validPayload, contextMember, "", installationMember, "")
	for _, fallback := range []bool{false, true} {
		v := newTestVerifier(publishedKeys())
		v.siteFallback = fallback
		got, err := verifyToken(t, v, signRaw(t, signers().primary, header, payload))
		checkResult(t, got, err, ReasonCloudID, Claims{})
	}
}

// TestVerifyEmptyPolicyValuesNeverMatch shows that a missing setting fails
// closed: an empty configured value matches nothing, not an empty claim.
func TestVerifyEmptyPolicyValuesNeverMatch(t *testing.T) {
	verify := func(t *testing.T, p Policy, payload string) (Claims, error) {
		v := NewVerifier(p, publishedKeys())
		v.now = func() time.Time { return synthNow }
		return verifyToken(t, v, signRaw(t, signers().primary, validHeader, payload))
	}
	t.Run("zero_policy", func(t *testing.T) {
		got, err := verify(t, Policy{}, validPayload)
		checkResult(t, got, err, ReasonAudience, Claims{})
	})
	t.Run("empty_app_id_and_aud", func(t *testing.T) {
		p := synthPolicy()
		p.AppID = ""
		got, err := verify(t, p, edit(t, validPayload, audMember, `"aud":"",`))
		checkResult(t, got, err, ReasonAudience, Claims{})
	})
	t.Run("empty_environment_id", func(t *testing.T) {
		p := synthPolicy()
		p.EnvironmentID = ""
		got, err := verify(t, p, edit(t, validPayload, envMember, `"environment":{"id":""},`))
		checkResult(t, got, err, ReasonEnvironment, Claims{})
	})
	t.Run("no_cloud_ids", func(t *testing.T) {
		p := synthPolicy()
		p.CloudIDs = nil
		got, err := verify(t, p, validPayload)
		checkResult(t, got, err, ReasonCloudID, Claims{})
	})
}
