// SPDX-License-Identifier: EUPL-1.2

package fit

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// FuzzVerify feeds arbitrary Authorization values to Verify (PLAN.md §13).
// Verify must never panic, and it may accept only the valid tokens signed
// below: anything else would be an accepted token without a valid
// signature. The seed corpus in testdata holds structural inputs only,
// because the signing keys exist only for the length of a test run.
func FuzzVerify(f *testing.F) {
	key := signers().primary
	tokens := []string{
		signRaw(f, key, validHeader, validPayload),
		signRaw(f, key, validHeader, edit(f, validPayload, audMember, `"aud":["`+synthAppID+`"],`)),
		signRaw(f, key, `{"kid":"`+synthKID+`","alg":"RS256"}`, edit(f, validPayload, expMember, `"exp":1.80000002e9,`)),
	}
	valid := make(map[string]bool)
	for _, tok := range tokens {
		valid[tok] = true
		f.Add("Bearer " + tok)
		f.Add("bearer " + tok)
		h, p, _ := parts(f, tok)
		f.Add("Bearer " + h + "." + p + ".")
		f.Add("Bearer " + h + "." + p + "." + segment("signature"))
	}
	v := newTestVerifier(publishedKeys())
	f.Fuzz(func(t *testing.T, authorization string) {
		claims, err := v.Verify(t.Context(), []string{authorization})
		if err != nil {
			var fe *Error
			if !errors.As(err, &fe) || claims != (Claims{}) {
				t.Fatalf("Verify = %+v, %v; want a rejection without claims", claims, err)
			}
			return
		}
		if len(authorization) < len("Bearer ") || !valid[authorization[len("Bearer "):]] {
			t.Fatalf("accepted a token that is not one of the signed seeds: %q", authorization)
		}
		if claims != validClaims {
			t.Fatalf("claims = %+v", claims)
		}
	})
}

// FuzzParseObject feeds arbitrary bytes to the strict JSON parser
// (PLAN.md §4.4, §13). It must never panic. Whatever it accepts must be
// valid UTF-8 and free of duplicate member names at every level: decoding
// into Go maps and re-marshaling keeps one member per name, so the member
// count would drop if a duplicate had been accepted.
func FuzzParseObject(f *testing.F) {
	for _, seed := range []string{
		validHeader, validPayload, `{}`, `{"a":1,"a":2}`, esc(`{"s":"~ud83d~ude00"}`),
		`{"o":{"l":[{"a":1},{"a":2}]}}`, nestedObjects(maxJSONDepth), `{} {}`, "{\"s\":\"\xff\"}",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		o, err := parseObject(raw)
		if err != nil {
			if o != nil {
				t.Fatal("parseObject returned an object with an error")
			}
			return
		}
		if !utf8.Valid(raw) {
			t.Fatal("accepted invalid UTF-8")
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			t.Fatalf("accepted a document encoding/json cannot decode: %v", err)
		}
		m, ok := v.(map[string]any)
		if !ok || len(m) != len(o) {
			t.Fatal("accepted something other than one object")
		}
		out, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := nameSeparators(out), nameSeparators(raw); got != want {
			t.Fatalf("re-marshaled document has %d members, input has %d: a duplicate name was accepted", got, want)
		}
		if _, err := parseObject(out); err != nil {
			t.Fatal("refused its own re-marshaled output")
		}
	})
}

// FuzzParseNumericDate checks the exp and nbf parser against an exact
// math/big oracle (PLAN.md §4.4, §13). FuzzVerify cannot reach it, because
// no mutated token keeps a valid signature.
func FuzzParseNumericDate(f *testing.F) {
	// Too long for a readable corpus file (see TestParseNumericDate).
	f.Add([]byte(clampBoundaryDate))
	f.Fuzz(func(t *testing.T, raw []byte) {
		for _, roundUp := range []bool{false, true} {
			got, err := parseNumericDate(raw, roundUp)
			var fe *Error
			if err != nil && (!errors.As(err, &fe) || fe.Reason != ReasonDates) {
				t.Fatalf("parseNumericDate error = %v, want reason %q", err, ReasonDates)
			}
			want, ok := numericDateOracle(string(raw), roundUp)
			switch {
			case ok && (err != nil || !got.Equal(want)):
				t.Fatalf("parseNumericDate(%.40q, roundUp=%v) = %v, %v; want %v", raw, roundUp, got.UTC(), err, want.UTC())
			// Verify passes only member values of a strict JSON document, so
			// the oracle's verdict binds for JSON values; any other input
			// must merely not panic.
			case !ok && err == nil && json.Valid(raw):
				t.Fatalf("parseNumericDate(%.40q, roundUp=%v) accepted what the oracle refuses", raw, roundUp)
			}
		}
	})
}

// unsignedJSONNumber is the JSON number grammar (RFC 8259 §6) without the
// minus sign, with the mantissa and the exponent as groups.
var unsignedJSONNumber = regexp.MustCompile(`^((?:0|[1-9][0-9]*)(?:\.[0-9]+)?)(?:[eE]([+-]?[0-9]+))?$`)

// oracleExponentLimit clamps exponents in numericDateOracle. For a literal of
// at most MaxTokenBytes a larger magnitude gives the same answer: far out of
// range when positive, a positive value below one nanosecond when negative.
// It is twice the parser's own clamp, so the two do not share a mistake.
const oracleExponentLimit = 4 * MaxTokenBytes

// numericDateOracle computes what parseNumericDate must return, with exact
// rational arithmetic: an unsigned JSON number of at most MaxTokenBytes and
// at most MaxNumericDateSeconds, cut to nanoseconds, down or, with roundUp,
// up.
func numericDateOracle(raw string, roundUp bool) (time.Time, bool) {
	m := unsignedJSONNumber.FindStringSubmatch(raw)
	if m == nil || len(raw) > MaxTokenBytes {
		return time.Time{}, false
	}
	exp, limit := new(big.Int), big.NewInt(oracleExponentLimit)
	if m[2] != "" {
		if _, ok := exp.SetString(m[2], 10); !ok {
			return time.Time{}, false
		}
	}
	if exp.CmpAbs(limit) > 0 {
		exp.Mul(limit, big.NewInt(int64(exp.Sign())))
	}
	v, ok := new(big.Rat).SetString(m[1] + "e" + exp.String())
	if !ok || v.Cmp(new(big.Rat).SetInt64(MaxNumericDateSeconds)) > 0 {
		return time.Time{}, false
	}
	ns := v.Mul(v, new(big.Rat).SetInt64(int64(time.Second)))
	q, r := new(big.Int).QuoRem(ns.Num(), ns.Denom(), new(big.Int))
	if roundUp && r.Sign() != 0 {
		q.Add(q, big.NewInt(1))
	}
	sec, nsec := new(big.Int).QuoRem(q, big.NewInt(int64(time.Second)), new(big.Int))
	return time.Unix(sec.Int64(), nsec.Int64()), true
}

// TestNumericDateOracle keeps the fuzz oracle honest on values whose answer
// is known without it.
func TestNumericDateOracle(t *testing.T) {
	cases := []struct {
		raw     string
		roundUp bool
		want    time.Time
		ok      bool
	}{
		{"1800000000.5", false, time.Unix(1800000000, 5e8), true},
		{"18E+8", false, time.Unix(1800000000, 0), true},
		{"0.0000000001", false, time.Unix(0, 0), true},
		{"0.0000000001", true, time.Unix(0, 1), true},
		{"1e-999999999", true, time.Unix(0, 1), true},
		{"253402300799", true, time.Unix(MaxNumericDateSeconds, 0), true},
		{"253402300799.0000000001", false, time.Time{}, false},
		{"1e999999999", false, time.Time{}, false},
		{clampBoundaryDate, false, time.Time{}, false},
		{"01", false, time.Time{}, false},
		{"-0", false, time.Time{}, false},
	}
	for _, tc := range cases {
		got, ok := numericDateOracle(tc.raw, tc.roundUp)
		if ok != tc.ok || ok && !got.Equal(tc.want) {
			t.Fatalf("numericDateOracle(%.40q, %v) = %v, %v; want %v, %v", tc.raw, tc.roundUp, got.UTC(), ok, tc.want.UTC(), tc.ok)
		}
	}
}

// FuzzParseJWKS feeds arbitrary documents to the JWKS parser (PLAN.md §4.5,
// §13). It must never panic, must fail with a fixed jwksError and no keys,
// and may keep only a bounded set of keys that meet every eligibility rule.
// Each kept key is checked against the document as encoding/json reads it:
// exactly one entry carries its kid, and that entry has the eligible kty,
// use and alg and the key's own n and e.
func FuzzParseJWKS(f *testing.F) {
	keys := testPublicKeys()
	f.Add(testJWKS(f, testJWK("k1", keys[0]), testJWK("k2", keys[1])))
	// Near misses of an accepted document: an encryption key, and a second
	// entry claiming the kept kid.
	f.Add(testJWKS(f, testJWK("k1", keys[0]), jwkWith(testJWK("k2", keys[1]), "use", "enc")))
	f.Add(testJWKS(f, testJWK("k1", keys[0]), map[string]any{"kty": "EC", "kid": "k1"}))
	// Atlassian's live form pads n (PLAN.md §4.5, 2026-10-16), and a near
	// miss with one "=" too many.
	f.Add(testJWKS(f, atlassianJWK("k1", keys[0]), atlassianJWK("k2", keys[1])))
	f.Add(testJWKS(f, jwkWith(atlassianJWK("k1", keys[0]), "n", base64.URLEncoding.EncodeToString(keys[0].N.Bytes())+"=")))
	f.Fuzz(func(t *testing.T, raw []byte) {
		got, err := parseJWKS(raw, discardLogger())
		if err != nil {
			var je jwksError
			if !errors.As(err, &je) || got != nil {
				t.Fatalf("parseJWKS = %d keys, %v; want no keys and a jwksError", len(got), err)
			}
			return
		}
		if len(got) == 0 || len(got) > MaxJWKSKeys {
			t.Fatalf("parseJWKS kept %d keys", len(got))
		}
		if _, err := parseObject(raw); err != nil {
			t.Fatal("accepted a document that is not strict JSON")
		}
		// parseObject refused duplicate names, so maps lose nothing here,
		// and map keys match names exactly, unlike struct fields. UseNumber
		// keeps a number too large for a float64 from failing the decode.
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var doc map[string]any
		if err := dec.Decode(&doc); err != nil {
			t.Fatalf("accepted a document encoding/json cannot decode: %v", err)
		}
		entries, _ := doc["keys"].([]any)
		for kid, key := range got {
			bits := key.N.BitLen()
			if kid == "" || key.N.Bit(0) == 0 || bits < MinRSAModulusBits || bits > MaxRSAModulusBits ||
				key.E < minRSAExponent || key.E > maxRSAExponent || key.E%2 == 0 {
				t.Fatalf("kept an ineligible key: kid %q, %d bits, e = %d", kid, bits, key.E)
			}
			var claims []map[string]any
			for _, e := range entries {
				if jwk, ok := e.(map[string]any); ok && jwk["kid"] == kid {
					claims = append(claims, jwk)
				}
			}
			if len(claims) != 1 {
				t.Fatalf("kept kid %q, which %d entries carry", kid, len(claims))
			}
			jwk := claims[0]
			use, useSet := jwk["use"]
			alg, algSet := jwk["alg"]
			if jwk["kty"] != "RSA" || useSet && use != "sig" || algSet && alg != "RS256" ||
				!jwkParamIs(jwk["n"], key.N.Bytes()) || !jwkParamIs(jwk["e"], big.NewInt(int64(key.E)).Bytes()) {
				t.Fatalf("kept kid %q from an ineligible or different entry: %v", kid, jwk)
			}
		}
	})
}

// jwkParamIs reports whether v is a string of base64url, unpadded or with
// exactly the padding its length needs, that decodes to want, by
// encoding/base64 rather than the parser's own decoder. Go's decoders skip
// CR and LF, which the parser refuses, so those fail here first.
func jwkParamIs(v any, want []byte) bool {
	s, ok := v.(string)
	if !ok || strings.ContainsAny(s, "\r\n") {
		return false
	}
	enc := base64.RawURLEncoding
	if strings.HasSuffix(s, "=") {
		enc = base64.URLEncoding
	}
	b, err := enc.Strict().DecodeString(s)
	return err == nil && bytes.Equal(b, want)
}

// nameSeparators counts the ':' bytes outside strings, which in valid JSON
// is the number of object members at every level.
func nameSeparators(raw []byte) int {
	n, inString, escaped := 0, false, false
	for _, c := range raw {
		switch {
		case escaped:
			escaped = false
		case inString && c == '\\':
			escaped = true
		case c == '"':
			inString = !inString
		case !inString && c == ':':
			n++
		}
	}
	return n
}

// TestNameSeparators keeps the fuzz oracle honest.
func TestNameSeparators(t *testing.T) {
	for raw, want := range map[string]int{
		`{}`:                          0,
		`{"a":1,"b":{"c":[{"d":2}]}}`: 4,
		`{"a:b":"c:d"}`:               1,
		`{"a\":":"\\","b":1}`:         2,
	} {
		if got := nameSeparators([]byte(raw)); got != want {
			t.Fatalf("nameSeparators(%q) = %d, want %d", raw, got, want)
		}
	}
}
