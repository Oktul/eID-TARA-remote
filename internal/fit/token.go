// SPDX-License-Identifier: EUPL-1.2

package fit

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

const (
	// MaxTokenBytes bounds the compact JWS before anything is decoded, so an
	// unauthenticated caller cannot make parsing expensive (PLAN.md §4.4
	// step 1).
	MaxTokenBytes = 8 << 10

	// MaxNumericDateSeconds is the largest accepted exp or nbf, the last
	// second of the year 9999 UTC (PLAN.md §4.4).
	MaxNumericDateSeconds = 253402300799
)

const (
	// bearerScheme is matched case-insensitively, as HTTP auth schemes are
	// (PLAN.md §4.4).
	bearerScheme = "Bearer"

	// algorithm is the only JWS algorithm the relay accepts (PLAN.md §4.4,
	// A-2).
	algorithm = "RS256"

	// maxDateDigits is the number of digits of MaxNumericDateSeconds: a date
	// with more integer digits is out of range without further arithmetic.
	maxDateDigits = 12

	// nanoDigits is the number of fraction digits a time.Time can hold.
	nanoDigits = 9

	// maxDateExponent clamps a NumericDate exponent. For a literal of at most
	// MaxTokenBytes a larger magnitude gives the same answer, so the clamp
	// changes no result but keeps "1e999999999" cheap and overflow-free.
	maxDateExponent = 2 * MaxTokenBytes
)

// bearerToken returns the compact JWS from the request's Authorization field
// values. Exactly one field is allowed. The token may contain only the
// base64url alphabet and '.', which also refuses other whitespace and
// comma-joined credentials (PLAN.md §4.4).
func bearerToken(values []string) (string, error) {
	if len(values) != 1 {
		return "", reject(ReasonAuthorization)
	}
	v := values[0]
	n := len(bearerScheme)
	if len(v) <= n+1 || !strings.EqualFold(v[:n], bearerScheme) || v[n] != ' ' {
		return "", reject(ReasonAuthorization)
	}
	token := v[n+1:]
	for i := 0; i < len(token); i++ {
		if !base64URLByte(token[i]) && token[i] != '.' {
			return "", reject(ReasonAuthorization)
		}
	}
	return token, nil
}

// jws is a compact JWS with its header and signature decoded. The payload
// stays encoded until the signature over it has verified (PLAN.md §4.4
// steps 3 and 4).
type jws struct {
	signingInput string // the header and payload parts exactly as received
	payload      string
	header       object
	signature    []byte
}

// parseCompact splits a compact JWS and decodes its header and signature
// (PLAN.md §4.4 steps 1 and 2). Every failure is ReasonTokenFormat.
func parseCompact(token string) (jws, error) {
	if len(token) > MaxTokenBytes || strings.Count(token, ".") != 2 {
		return jws{}, reject(ReasonTokenFormat)
	}
	h, rest, _ := strings.Cut(token, ".")
	p, s, _ := strings.Cut(rest, ".")
	// Go's base64 decoder silently skips '\r' and '\n', even in strict mode,
	// so the alphabet is checked before any part is decoded.
	if !base64URL(h) || !base64URL(p) || !base64URL(s) {
		return jws{}, reject(ReasonTokenFormat)
	}
	raw, err := decodePart(h)
	if err != nil {
		return jws{}, reject(ReasonTokenFormat)
	}
	header, err := parseObject(raw)
	if err != nil {
		return jws{}, reject(ReasonTokenFormat)
	}
	sig, err := decodePart(s)
	if err != nil {
		return jws{}, reject(ReasonTokenFormat)
	}
	return jws{signingInput: token[:len(h)+1+len(p)], payload: p, header: header, signature: sig}, nil
}

// base64URL reports whether part is non-empty and only uses the unpadded
// base64url alphabet.
func base64URL(part string) bool {
	for i := 0; i < len(part); i++ {
		if !base64URLByte(part[i]) {
			return false
		}
	}
	return part != ""
}

func base64URLByte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

// decodePart decodes a string whose alphabet base64URL has checked: a token
// part or a JWK parameter. Strict mode also refuses non-canonical trailing
// bits, so each value has exactly one encoding (PLAN.md §4.4, §4.5).
func decodePart(part string) ([]byte, error) {
	return base64.RawURLEncoding.Strict().DecodeString(part)
}

// checkHeader applies the JWS header rules and returns the key ID
// (PLAN.md §4.4 step 2). The refused members would let a token name its own
// key or key source (jku, jwk, x5u, x5c), change what is signed (crit, b64)
// or compress the payload (zip); keys only ever come from the cache.
func checkHeader(h object) (string, error) {
	if alg, ok, err := h.str("alg"); err != nil || !ok || alg != algorithm {
		return "", reject(ReasonHeader)
	}
	kid, ok, err := h.str("kid")
	if err != nil || !ok || kid == "" {
		return "", reject(ReasonHeader)
	}
	for _, name := range [...]string{"crit", "jku", "jwk", "x5u", "x5c", "zip", "b64"} {
		if _, ok := h[name]; ok {
			return "", reject(ReasonHeader)
		}
	}
	return kid, nil
}

// parseNumericDate parses an exp or nbf claim without floating point, so no
// rounding or overflow can move a boundary (PLAN.md §4.4). raw must be an
// unsigned JSON number in [0, MaxNumericDateSeconds]; a missing claim (empty
// raw), null, a string or a negative number is refused. Sub-nanosecond
// fractions are cut down for exp and up for nbf (roundUp), so an inexact
// date can only shorten the validity window. Every failure is ReasonDates.
func parseNumericDate(raw json.RawMessage, roundUp bool) (time.Time, error) {
	if len(raw) == 0 || len(raw) > MaxTokenBytes || !isDigit(raw[0]) {
		return time.Time{}, reject(ReasonDates)
	}
	// The value is digits · 10^(exp - fracLen), with digits the integer and
	// fraction digits together.
	digits := make([]byte, 0, len(raw))
	i := 0
	for ; i < len(raw) && isDigit(raw[i]); i++ {
		digits = append(digits, raw[i])
	}
	fracLen := 0
	if i < len(raw) && raw[i] == '.' {
		i++
		for ; i < len(raw) && isDigit(raw[i]); i++ {
			digits = append(digits, raw[i])
			fracLen++
		}
		if fracLen == 0 {
			return time.Time{}, reject(ReasonDates)
		}
	}
	exp := 0
	if i < len(raw) && (raw[i] == 'e' || raw[i] == 'E') {
		i++
		negative := i < len(raw) && raw[i] == '-'
		if i < len(raw) && (raw[i] == '+' || raw[i] == '-') {
			i++
		}
		start := i
		for ; i < len(raw) && isDigit(raw[i]); i++ {
			exp = min(exp*10+int(raw[i]-'0'), maxDateExponent)
		}
		if i == start {
			return time.Time{}, reject(ReasonDates)
		}
		if negative {
			exp = -exp
		}
	}
	if i != len(raw) {
		return time.Time{}, reject(ReasonDates)
	}

	d := bytes.TrimLeft(digits, "0")
	if len(d) == 0 {
		return time.Unix(0, 0), nil
	}
	// intLen is the number of digits of d before the decimal point; positions
	// outside d are zeros.
	intLen := len(d) + exp - fracLen
	if intLen > maxDateDigits {
		return time.Time{}, reject(ReasonDates)
	}
	digit := func(p int) int64 {
		if p >= 0 && p < len(d) {
			return int64(d[p] - '0')
		}
		return 0
	}
	var sec, nsec int64
	for p := range intLen {
		sec = sec*10 + digit(p)
	}
	for p := intLen; p < intLen+nanoDigits; p++ {
		nsec = nsec*10 + digit(p)
	}
	belowNano := false
	for p := max(intLen+nanoDigits, 0); p < len(d) && !belowNano; p++ {
		belowNano = d[p] != '0'
	}
	if sec > MaxNumericDateSeconds || sec == MaxNumericDateSeconds && (nsec != 0 || belowNano) {
		return time.Time{}, reject(ReasonDates)
	}
	if roundUp && belowNano {
		if nsec++; nsec == int64(time.Second) {
			sec, nsec = sec+1, 0
		}
	}
	return time.Unix(sec, nsec), nil
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
