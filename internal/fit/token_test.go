// SPDX-License-Identifier: EUPL-1.2

package fit

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// wantRejection fails t unless err is a rejection with reason want.
func wantRejection(t *testing.T, err error, want Reason) {
	t.Helper()
	var fe *Error
	if !errors.As(err, &fe) || fe.Reason != want {
		t.Fatalf("error = %v, want reason %q", err, want)
	}
}

func TestBearerToken(t *testing.T) {
	t.Run("returns_the_token_after_one_space", func(t *testing.T) {
		for _, v := range []string{"Bearer a.b.c", "bearer a.b.c", "BEARER a.b.c"} {
			got, err := bearerToken([]string{v})
			if err != nil || got != "a.b.c" {
				t.Fatalf("bearerToken(%q) = %q, %v", v, got, err)
			}
		}
	})
	t.Run("shortest_token_accepted", func(t *testing.T) {
		if got, err := bearerToken([]string{"Bearer x"}); err != nil || got != "x" {
			t.Fatalf("bearerToken = %q, %v", got, err)
		}
	})
	// Every byte outside the base64url alphabet and '.' is refused, which
	// covers whitespace, commas and quoting in one rule.
	t.Run("only_base64url_and_dot", func(t *testing.T) {
		for c := range 256 {
			b := byte(c)
			_, err := bearerToken([]string{"Bearer a" + string(b) + "b"})
			want := base64URLByte(b) || b == '.'
			if (err == nil) != want {
				t.Fatalf("byte %#x: error = %v", b, err)
			}
			if err != nil {
				wantRejection(t, err, ReasonAuthorization)
			}
		}
	})
}

// TestParseCompactRefusesNonBase64URL calls parseCompact directly, because
// bearerToken already refuses these bytes. Go's base64 decoder ignores '\r'
// and '\n', so without the alphabet check the CR/LF cases would decode.
func TestParseCompactRefusesNonBase64URL(t *testing.T) {
	h, p, s := parts(t, signRaw(t, signers().primary, validHeader, validPayload))
	if _, err := parseCompact(h + "." + p + "." + s); err != nil {
		t.Fatalf("valid token: %v", err)
	}
	insert := func(part, x string) string { return part[:4] + x + part[4:] }
	cases := []struct{ name, token string }{
		{"crlf_in_header", insert(h, "\r\n") + "." + p + "." + s},
		{"lf_in_header", insert(h, "\n") + "." + p + "." + s},
		{"crlf_in_payload", h + "." + insert(p, "\r\n") + "." + s},
		{"crlf_in_signature", h + "." + p + "." + insert(s, "\r\n")},
		{"space_in_header", insert(h, " ") + "." + p + "." + s},
		{"tab_in_signature", h + "." + p + "." + insert(s, "\t")},
		{"padded_header", h + "==" + "." + p + "." + s},
		{"padded_signature", h + "." + p + "." + s + "=="},
		{"standard_alphabet_plus", h + "." + insert(p, "+") + "." + s},
		{"standard_alphabet_slash", h + "." + p + "." + insert(s, "/")},
		{"nul_in_payload", h + "." + insert(p, "\x00") + "." + s},
		{"non_ascii_in_payload", h + "." + insert(p, "é") + "." + s},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseCompact(tc.token)
			wantRejection(t, err, ReasonTokenFormat)
		})
	}
}

func TestParseCompactSizeLimit(t *testing.T) {
	h, _, s := parts(t, signRaw(t, signers().primary, validHeader, validPayload))
	// The payload is not decoded here, so any base64url filler will do.
	filler := func(total int) string {
		return h + "." + strings.Repeat("A", total-len(h)-len(s)-2) + "." + s
	}
	if _, err := parseCompact(filler(MaxTokenBytes)); err != nil {
		t.Fatalf("token of MaxTokenBytes: %v", err)
	}
	_, err := parseCompact(filler(MaxTokenBytes + 1))
	wantRejection(t, err, ReasonTokenFormat)
}

// clampBoundaryDate is 1e12, out of range, spelled with an 8181-digit
// fraction and the exponent 8193 so that it still fits in a token. An
// exponent clamp below 8193 would read it as an in-range 1e11.
var clampBoundaryDate = "0." + strings.Repeat("0", 8180) + "1e8193"

func TestParseNumericDate(t *testing.T) {
	if len(clampBoundaryDate) > MaxTokenBytes {
		t.Fatal("clampBoundaryDate is refused for its length, not its value")
	}
	at := time.Unix
	cases := []struct {
		name        string
		raw         string
		floor, ceil time.Time // ignored when !ok
		ok          bool
	}{
		{"integer", "1800000000", at(1800000000, 0), at(1800000000, 0), true},
		{"zero", "0", at(0, 0), at(0, 0), true},
		{"zero_fraction", "0.0", at(0, 0), at(0, 0), true},
		{"zero_with_huge_exponent", "0e999999999", at(0, 0), at(0, 0), true},
		{"half_second", "1800000000.5", at(1800000000, 5e8), at(1800000000, 5e8), true},
		{"one_nanosecond", "1800000000.000000001", at(1800000000, 1), at(1800000000, 1), true},
		{"below_one_nanosecond", "1800000000.0000000001", at(1800000000, 0), at(1800000000, 1), true},
		{"rounds_up_into_next_second", "1800000000.9999999999", at(1800000000, 999999999), at(1800000001, 0), true},
		{"trailing_fraction_zeros", "1800000000.500000000000", at(1800000000, 5e8), at(1800000000, 5e8), true},
		{"exponent", "18e8", at(1800000000, 0), at(1800000000, 0), true},
		{"exponent_upper_case_with_plus", "1.8E+9", at(1800000000, 0), at(1800000000, 0), true},
		{"negative_exponent", "18000000005e-1", at(1800000000, 5e8), at(1800000000, 5e8), true},
		{"fraction_and_exponent", "1.8000000005e9", at(1800000000, 5e8), at(1800000000, 5e8), true},
		{"leading_zero_mantissa", "0.18e10", at(1800000000, 0), at(1800000000, 0), true},
		{"tiny_by_exponent", "1e-999999999", at(0, 0), at(0, 1), true},
		{"tiny_by_long_fraction", "0." + strings.Repeat("0", 5000) + "1", at(0, 0), at(0, 1), true},
		{"max", "253402300799", at(MaxNumericDateSeconds, 0), at(MaxNumericDateSeconds, 0), true},
		{"max_with_zero_fraction", "253402300799.000", at(MaxNumericDateSeconds, 0), at(MaxNumericDateSeconds, 0), true},
		{"max_by_exponent", "2.53402300799e11", at(MaxNumericDateSeconds, 0), at(MaxNumericDateSeconds, 0), true},
		{"max_by_scaled_mantissa", "2534023007990e-1", at(MaxNumericDateSeconds, 0), at(MaxNumericDateSeconds, 0), true},

		{"above_max", "253402300800", time.Time{}, time.Time{}, false},
		{"max_plus_half", "253402300799.5", time.Time{}, time.Time{}, false},
		{"max_plus_below_one_nanosecond", "253402300799.0000000001", time.Time{}, time.Time{}, false},
		{"thirteen_digits", "1000000000000", time.Time{}, time.Time{}, false},
		{"exponent_out_of_range", "1e12", time.Time{}, time.Time{}, false},
		{"huge_exponent", "1e999999999", time.Time{}, time.Time{}, false},
		{"exponent_beyond_int64", "1e99999999999999999999", time.Time{}, time.Time{}, false},
		{"exponent_with_many_digits", "1e" + strings.Repeat("9", 5000), time.Time{}, time.Time{}, false},
		{"exponent_clamp_keeps_long_literal_out_of_range", clampBoundaryDate, time.Time{}, time.Time{}, false},
		{"literal_longer_than_a_token", "0." + strings.Repeat("0", MaxTokenBytes), time.Time{}, time.Time{}, false},
		{"negative", "-1", time.Time{}, time.Time{}, false},
		{"negative_zero", "-0", time.Time{}, time.Time{}, false},
		{"plus_sign", "+1", time.Time{}, time.Time{}, false},
		{"leading_dot", ".5", time.Time{}, time.Time{}, false},
		{"trailing_dot", "1.", time.Time{}, time.Time{}, false},
		{"dot_before_exponent", "1.e5", time.Time{}, time.Time{}, false},
		{"empty_exponent", "1e", time.Time{}, time.Time{}, false},
		{"signed_empty_exponent", "1e+", time.Time{}, time.Time{}, false},
		{"two_dots", "1.2.3", time.Time{}, time.Time{}, false},
		{"two_exponents", "1e2e3", time.Time{}, time.Time{}, false},
		{"string", `"1800000000"`, time.Time{}, time.Time{}, false},
		{"null", "null", time.Time{}, time.Time{}, false},
		{"bool", "true", time.Time{}, time.Time{}, false},
		{"leading_space", " 1", time.Time{}, time.Time{}, false},
		{"trailing_space", "1 ", time.Time{}, time.Time{}, false},
		{"hex", "0x10", time.Time{}, time.Time{}, false},
		{"comma_decimal", "1,5", time.Time{}, time.Time{}, false},
		{"nan", "NaN", time.Time{}, time.Time{}, false},
		{"infinity", "Infinity", time.Time{}, time.Time{}, false},
		{"empty", "", time.Time{}, time.Time{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, roundUp := range []bool{false, true} {
				got, err := parseNumericDate([]byte(tc.raw), roundUp)
				if !tc.ok {
					wantRejection(t, err, ReasonDates)
					continue
				}
				want := tc.floor
				if roundUp {
					want = tc.ceil
				}
				if err != nil || !got.Equal(want) {
					t.Fatalf("parseNumericDate(roundUp=%v) = %v, %v; want %v", roundUp, got.UTC(), err, want.UTC())
				}
			}
		})
	}
}
