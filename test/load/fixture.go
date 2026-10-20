// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// Synthetic identities. They have the shape the relay's settings require,
// but name no real app, environment, site or installation (CONTRIBUTING.md,
// Tests). Fixed values let one relay env file serve every run.
const (
	appID          = "ari:cloud:ecosystem::app/11111111-1111-4111-8111-111111111111"
	environmentID  = "ari:cloud:ecosystem::environment/11111111-1111-4111-8111-111111111111/22222222-2222-4222-8222-222222222222"
	cloudID        = "33333333-3333-4333-8333-333333333333"
	installationID = "ari:cloud:ecosystem::installation/44444444-4444-4444-8444-444444444444"
	keyID          = "load-test-key"
)

const (
	fitIssuer = "forge/invocation-token" // PLAN.md §4.4
	jwksPath  = "/.well-known/jwks.json"
	tokenPath = "/oidc/token"

	// rsaKeyBits is the smallest modulus the relay accepts (PLAN.md §4.5),
	// which is also what Atlassian's keys use.
	rsaKeyBits = 2048
	// fitLifetime matches Atlassian's example token (PLAN.md §4.4).
	fitLifetime = 25 * time.Second
	// fitRemint keeps every token far from expiry when it is sent. RS256
	// signing costs about a millisecond, so signing once per request would
	// take CPU from the relay being measured.
	fitRemint = 5 * time.Second

	// certLifetime outlasts the longest possible run, every scenario at
	// maxDuration. certBackdate lets a relay whose clock lags this machine's
	// (a VM, a container host) accept the certificates.
	certLifetime = 30 * 24 * time.Hour
	certBackdate = time.Hour
	serialBits   = 128
)

type jwsHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// fitClaims carries the claims the relay checks (PLAN.md §4.4) plus iat and
// app.id, which real FITs also carry and the relay ignores.
type fitClaims struct {
	Iss     string     `json:"iss"`
	Aud     string     `json:"aud"`
	Iat     int64      `json:"iat"`
	Nbf     int64      `json:"nbf"`
	Exp     int64      `json:"exp"`
	App     fitApp     `json:"app"`
	Context fitContext `json:"context"`
}

type fitApp struct {
	ID             string         `json:"id"`
	InstallationID string         `json:"installationId"`
	Environment    fitEnvironment `json:"environment"`
}

type fitEnvironment struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type fitContext struct {
	CloudID string `json:"cloudId"`
}

// fitSet is one signed FIT and the parts its invalid variants reuse.
type fitSet struct {
	valid        string // passes every relay check
	badSignature string // valid's header and payload with one signature bit flipped
	payload      string // the encoded payload part of valid
	signature    string // the encoded signature part of valid
}

// minter signs FITs with the run's key and shares them between workers.
type minter struct {
	key *rsa.PrivateKey
	now func() time.Time

	mu       sync.Mutex // guards cur and mintedAt
	cur      fitSet
	mintedAt time.Time
}

func newMinter(key *rsa.PrivateKey, now func() time.Time) *minter {
	return &minter{key: key, now: now}
}

// get returns a FIT set that is less than fitRemint old.
func (m *minter) get() (fitSet, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if m.cur.valid != "" && now.Sub(m.mintedAt) < fitRemint {
		return m.cur, nil
	}
	s, err := mint(m.key, now)
	if err != nil {
		return fitSet{}, err
	}
	m.cur, m.mintedAt = s, now
	return s, nil
}

// mint signs a FIT valid from now for fitLifetime: an RS256 compact JWS over
// the parts exactly as encoded, which is what the relay verifies (PLAN.md
// §4.4).
func mint(key *rsa.PrivateKey, now time.Time) (fitSet, error) {
	header, err := encodePart(jwsHeader{Alg: "RS256", Kid: keyID, Typ: "JWT"})
	if err != nil {
		return fitSet{}, err
	}
	nbf := now.Unix()
	payload, err := encodePart(fitClaims{
		Iss: fitIssuer,
		Aud: appID,
		Iat: nbf,
		Nbf: nbf,
		Exp: nbf + int64(fitLifetime/time.Second),
		App: fitApp{
			ID:             appID,
			InstallationID: installationID,
			Environment:    fitEnvironment{Type: "DEVELOPMENT", ID: environmentID},
		},
		Context: fitContext{CloudID: cloudID},
	})
	if err != nil {
		return fitSet{}, err
	}
	digest := sha256.Sum256([]byte(header + "." + payload))
	sig, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, digest[:])
	if err != nil {
		return fitSet{}, err
	}
	// Flipping a bit and re-encoding keeps the part canonical base64url, so
	// the relay gets as far as the signature check before it rejects.
	bad := slices.Clone(sig)
	bad[len(bad)-1] ^= 1
	signature := b64(sig)
	return fitSet{
		valid:        header + "." + payload + "." + signature,
		badSignature: header + "." + payload + "." + b64(bad),
		payload:      payload,
		signature:    signature,
	}, nil
}

// unknownKeyFIT puts s's payload and signature under a header naming kid.
// The relay must look kid up before it can check anything else, so every
// distinct kid exercises the unknown-key path (PLAN.md §4.5).
func unknownKeyFIT(s fitSet, kid string) (string, error) {
	header, err := encodePart(jwsHeader{Alg: "RS256", Kid: kid, Typ: "JWT"})
	if err != nil {
		return "", err
	}
	return header + "." + s.payload + "." + s.signature, nil
}

func encodePart(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return b64(b), nil
}

// b64 is the unpadded base64url encoding the relay insists on (PLAN.md §4.4).
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

type jwks struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// jwksDocument publishes pub as the only key, with every member the relay
// checks before it trusts a key (PLAN.md §4.5).
func jwksDocument(pub *rsa.PublicKey) ([]byte, error) {
	return json.Marshal(jwks{Keys: []jwk{{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: keyID,
		N:   b64(pub.N.Bytes()),
		E:   b64(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

// newCertificates creates a throwaway CA and a server certificate for host
// signed by it. The relay trusts the CA through SSL_CERT_FILE (JWKS) and
// RELAY_UPSTREAM_CA_FILE (upstream), so its TLS checks stay on during a run
// (PLAN.md §4.5, §5). Only the CA certificate leaves memory. ECDSA keeps
// start-up fast; the relay's clients accept it like any key type Go supports.
func newCertificates(host string, now time.Time) (caPEM []byte, server tls.Certificate, err error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	caSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), serialBits))
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "eID Forge Remote load test CA"},
		NotBefore:             now.Add(-certBackdate),
		NotAfter:              now.Add(certLifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, tls.Certificate{}, err
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	leafSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), serialBits))
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-certBackdate),
		NotAfter:     now.Add(certLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		leafTemplate.IPAddresses = []net.IP{ip}
	} else {
		leafTemplate.DNSNames = []string{host}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return caPEM, tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}, nil
}

// fixture is the HTTPS side the relay calls during a run: the JWKS and the
// fake upstream token endpoint (PLAN.md §3). Its counters show whether a
// rejected request reached the upstream (§4.2) and how often unknown key IDs
// made the relay fetch the JWKS (§4.5).
type fixture struct {
	jwks         []byte
	requestBody  []byte // what every forwarded request must carry unchanged
	responseBody []byte
	delay        time.Duration

	upstreamCalls atomic.Int64
	jwksFetches   atomic.Int64
	// jwksDown makes the JWKS answer 503, as an unreachable CDN would
	// (the jwks-outage scenario, PLAN.md §4.5).
	jwksDown atomic.Bool
}

func (f *fixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == jwksPath:
		f.jwksFetches.Add(1)
		if f.jwksDown.Load() {
			http.Error(w, "jwks down for the outage scenario", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// A failed write means the relay went away; its fetch fails on its own.
		_, _ = w.Write(f.jwks)
	case r.Method == http.MethodPost && r.URL.Path == tokenPath:
		f.upstreamCalls.Add(1)
		f.token(w, r)
	default:
		http.NotFound(w, r)
	}
}

// token checks that the relay passed the body on unchanged (PLAN.md §5) and
// answers a full-sized body after the configured delay, which holds the
// relay's concurrency slot as a slow provider would. A changed body answers
// 400, which the generator reports as an unexpected upstream status.
func (f *fixture) token(w http.ResponseWriter, r *http.Request) {
	got, err := io.ReadAll(io.LimitReader(r.Body, int64(len(f.requestBody))+1))
	if err != nil {
		return // the relay cancelled the call; nobody is left to answer
	}
	if !bytes.Equal(got, f.requestBody) {
		http.Error(w, "request body changed", http.StatusBadRequest)
		return
	}
	if f.delay > 0 {
		t := time.NewTimer(f.delay)
		defer t.Stop()
		select {
		case <-t.C:
		case <-r.Context().Done():
			return
		}
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	// A failed write means the relay went away; it reports that itself.
	_, _ = w.Write(f.responseBody)
}

// Fixture server bounds. The relay is the only client, but every read and
// write is still bounded (CONTRIBUTING.md, explicit HTTP).
const (
	fixtureReadHeaderTimeout = 5 * time.Second
	fixtureIOTimeout         = 30 * time.Second // body read and answer, on top of -upstream-delay
	fixtureIdleTimeout       = 90 * time.Second
	fixtureMaxHeaderBytes    = 16 << 10
)

func newFixtureServer(f *fixture, cert tls.Certificate, errorLog io.Writer) *http.Server {
	return &http.Server{
		Handler:           f,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: fixtureReadHeaderTimeout,
		ReadTimeout:       fixtureIOTimeout,
		WriteTimeout:      fixtureIOTimeout + f.delay,
		IdleTimeout:       fixtureIdleTimeout,
		MaxHeaderBytes:    fixtureMaxHeaderBytes,
		// TLS handshake failures land here; they are how an operator sees
		// that the relay does not trust the CA yet.
		ErrorLog: log.New(errorLog, "load: fixture: ", 0),
	}
}

// fill returns n bytes of unit repeated. Request and response use different
// units, so a relay that echoed one as the other would fail the comparison.
func fill(n int, unit string) []byte {
	return bytes.Repeat([]byte(unit), n/len(unit)+1)[:n]
}
