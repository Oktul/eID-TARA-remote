// SPDX-License-Identifier: EUPL-1.2

package server_test

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// builtInTLS returns RELAY_TLS_CERT_FILE and RELAY_TLS_KEY_FILE settings for
// a loopback certificate generated for this test, so no key is committed
// (CONTRIBUTING.md, Tests), and a pool that trusts it.
func builtInTLS(t *testing.T) (map[string]string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "relay test listener"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return map[string]string{"RELAY_TLS_CERT_FILE": certFile, "RELAY_TLS_KEY_FILE": keyFile}, pool
}

// TestBuiltInTLS proves the built-in TLS listener of PLAN.md §8 (S-10)
// through Server.Run: TLS 1.2 or later, HTTP/1.1 only even when the client
// offers HTTP/2 (§7), and the relay's own answers over it. A TLS handshake
// error, which net/http logs with the client's ALPN offer, reaches the log
// only as the fixed message (§10).
func TestBuiltInTLS(t *testing.T) {
	env, roots := builtInTLS(t)
	r := newRelay(t, relayOptions{run: true, env: env})
	dial := func(c *tls.Config) (*tls.Conn, error) {
		c.RootCAs, c.ServerName = roots, "127.0.0.1"
		d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: waitTimeout}, Config: c}
		conn, err := d.Dial("tcp", r.addr)
		if err != nil {
			return nil, err
		}
		return conn.(*tls.Conn), nil
	}

	t.Run("h2_offer_negotiates_http1", func(t *testing.T) {
		conn, err := dial(&tls.Config{NextProtos: []string{"h2", "http/1.1"}})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }() // one exchange per connection
		if p := conn.ConnectionState().NegotiatedProtocol; p != "http/1.1" {
			t.Fatalf("negotiated %q, want http/1.1", p)
		}
		if err := conn.SetDeadline(time.Now().Add(waitTimeout)); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(conn, requestText("GET", "/livez", nil)); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		expectHealthy(t, reply{status: resp.StatusCode, header: resp.Header, body: string(b)})
	})

	t.Run("tls_1_1_refused", func(t *testing.T) {
		// The client allows the old versions, so only the relay can refuse.
		conn, err := dial(&tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11})
		if err == nil {
			_ = conn.Close() // the handshake should not have succeeded
			t.Fatal("TLS 1.1 handshake succeeded")
		}
		var oe *net.OpError
		if !errors.As(err, &oe) || oe.Op != "remote error" {
			t.Errorf("handshake error %v, want a refusal by the relay", err)
		}
	})

	t.Run("handshake_error_not_logged", func(t *testing.T) {
		before := strings.Count(r.logs.String(), `"msg":"http server error"`)
		conn, err := dial(&tls.Config{NextProtos: []string{secretMarker}})
		if err == nil {
			_ = conn.Close() // the handshake should not have succeeded
			t.Fatal("handshake with an unknown ALPN protocol succeeded")
		}
		waitUntil(t, "the handshake error log line", func() bool {
			return strings.Count(r.logs.String(), `"msg":"http server error"`) > before
		})
		if strings.Contains(r.logs.String(), secretMarker) {
			t.Error("log contains the client's ALPN offer")
		}
	})
}
