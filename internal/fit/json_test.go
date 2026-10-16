// SPDX-License-Identifier: EUPL-1.2

package fit

import (
	"encoding/json"
	"strings"
	"testing"
)

// esc turns every '~' in s into a backslash. Fixtures spell a \u escape as
// ~u0061 because the editing tools that first wrote these files decoded each
// valid escape into its character, which silently turned the escaped cases
// into copies of their plain siblings.
func esc(s string) string { return strings.ReplaceAll(s, "~", "\\") }

// requireEscape fails t when a case named *_escaped, or *_escaped_accepted,
// holds no backslash-u escape in doc, so it cannot quietly test the plain
// spelling instead.
func requireEscape(t testing.TB, name, doc string) {
	t.Helper()
	if strings.HasSuffix(strings.TrimSuffix(name, "_accepted"), "_escaped") && !strings.Contains(doc, esc("~u")) {
		t.Fatalf("case %s holds no backslash-u escape: %q", name, doc)
	}
}

// nestedObjects returns an object nested depth levels deep, counting the
// outermost one.
func nestedObjects(depth int) string {
	return strings.Repeat(`{"a":`, depth-1) + `{}` + strings.Repeat(`}`, depth-1)
}

// nestedArrays returns an object holding arrays, depth levels in all.
func nestedArrays(depth int) string {
	return `{"a":` + strings.Repeat(`[`, depth-1) + strings.Repeat(`]`, depth-1) + `}`
}

func TestParseObjectAcceptsStrictJSON(t *testing.T) {
	cases := []struct{ name, raw string }{
		{"empty_object", `{}`},
		{"members_of_every_type", `{"s":"x","n":-1.5e-3,"b":true,"f":false,"z":null,"o":{"k":[1,"x",{}]},"a":[]}`},
		{"surrounding_whitespace", " \t\r\n{ \"a\" : 1 } \t\r\n"},
		{"same_name_at_different_levels", `{"a":{"a":{"a":1}}}`},
		{"same_name_in_sibling_objects", `{"l":[{"a":1},{"a":2}],"m":{"a":3}}`},
		{"names_differing_only_in_case", `{"a":1,"A":2}`},
		{"escaped_quote_in_name", `{"a\"b":1,"a\\b":2}`},
		{"escaped_backslash_before_u", `{"s":"\\ud800"}`},
		{"utf8_text", `{"tööline":"😀"}`},
		{"bmp_characters_escaped", esc(`{"~u00e9":"~u20ac"}`)},
		{"surrogate_pair_escaped", esc(`{"s":"~ud83d~ude00"}`)},
		{"surrogate_pair_upper_case_hex_escaped", esc(`{"s":"~uD83D~uDE00"}`)},
		{"surrogate_pair_in_name_escaped", esc(`{"~ud83d~ude00":1}`)},
		{"surrogate_pair_between_other_escapes_escaped", esc(`{"s":"\n~ud83d~ude00\\"}`)},
		{"huge_number_kept_raw", `{"n":1e999999999}`},
		{"nesting_at_limit", nestedObjects(maxJSONDepth)},
		{"array_nesting_at_limit", nestedArrays(maxJSONDepth)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requireEscape(t, tc.name, tc.raw)
			if _, err := parseObject([]byte(tc.raw)); err != nil {
				t.Fatalf("parseObject(%q) = %v", tc.raw, err)
			}
		})
	}
}

// rejectCase is a document parseObject must refuse.
type rejectCase struct{ name, raw string }

func runRejectCases(t *testing.T, cases []rejectCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requireEscape(t, tc.name, tc.raw)
			o, err := parseObject([]byte(tc.raw))
			if err != errJSON || o != nil {
				t.Fatalf("parseObject(%q) = %v, %v; want nil, errJSON", tc.raw, o, err)
			}
		})
	}
}

func TestParseObjectRejectsDuplicateNames(t *testing.T) {
	runRejectCases(t, []rejectCase{
		{"top_level", `{"a":1,"a":2}`},
		{"top_level_same_value", `{"a":1,"a":1}`},
		{"top_level_different_types", `{"a":null,"a":{}}`},
		{"after_nested_value", `{"a":{"x":1},"b":2,"a":3}`},
		{"one_escaped", esc(`{"a":1,"~u0061":2}`)},
		{"both_escaped", esc(`{"~u0061":1,"~u0061":2}`)},
		{"upper_and_lower_case_hex_escaped", esc(`{"~u004A":1,"~u004a":2}`)},
		{"escaped_solidus", `{"a/b":1,"a\/b":2}`},
		{"utf8_and_escaped", esc(`{"é":1,"~u00e9":2}`)},
		{"utf8_and_surrogate_pair_escaped", esc(`{"😀":1,"~ud83d~ude00":2}`)},
		{"in_nested_object", `{"o":{"a":1,"a":2}}`},
		{"in_nested_object_escaped", esc(`{"o":{"a":1,"~u0061":2}}`)},
		{"in_array_element", `{"l":[{"a":1,"a":2}]}`},
		{"in_array_element_escaped", esc(`{"l":[{"a":1,"~u0061":2}]}`)},
		{"in_later_array_element", `{"l":[{"a":1},{"b":1,"b":2}]}`},
		{"deep", `{"a":{"b":{"c":[{"d":{"e":1,"e":1}}]}}}`},
	})
}

func TestParseObjectNamesAreCaseSensitive(t *testing.T) {
	o, err := parseObject([]byte(`{"iss":"a","ISS":"b","Iss":"c"}`))
	if err != nil || len(o) != 3 {
		t.Fatalf("parseObject = %v, %v; want three members", o, err)
	}
	for name, want := range map[string]string{"iss": "a", "ISS": "b", "Iss": "c"} {
		if got, ok, err := o.str(name); err != nil || !ok || got != want {
			t.Fatalf("str(%q) = %q, %v, %v; want %q", name, got, ok, err, want)
		}
	}
	if _, ok, err := o.str("iSS"); ok || err != nil {
		t.Fatal("lookup matched a name that differs in case")
	}
}

func TestParseObjectRejectsInvalidUnicode(t *testing.T) {
	runRejectCases(t, []rejectCase{
		{"invalid_byte_in_value", "{\"s\":\"\xff\"}"},
		{"invalid_byte_in_name", "{\"\xfe\":1}"},
		{"invalid_byte_outside_strings", "{\"s\":1\xff}"},
		{"overlong_encoding", "{\"s\":\"\xc0\xaf\"}"},
		{"utf8_encoded_surrogate", "{\"s\":\"\xed\xa0\x80\"}"},
		{"truncated_sequence", "{\"s\":\"\xe2\x82\"}"},
		{"code_point_above_unicode", "{\"s\":\"\xf4\x90\x80\x80\"}"},
		{"lone_high_surrogate", `{"s":"\ud800"}`},
		{"lone_low_surrogate", `{"s":"\udc00"}`},
		{"reversed_pair", `{"s":"\udc00\ud800"}`},
		{"high_then_text", `{"s":"\ud800x"}`},
		{"high_then_bmp_escaped", esc(`{"s":"~ud800~u0041"}`)},
		{"high_then_code_unit_above_low_surrogates_escaped", esc(`{"s":"~ud800~ue000"}`)},
		{"high_then_other_escape", `{"s":"\ud800\n"}`},
		{"high_then_escaped_backslash", `{"s":"\ud800\\udc00"}`},
		// The next two put low-surrogate hex digits where a following \u
		// escape's digits would be, without the \u.
		{"high_then_text_resembling_low", `{"s":"\ud800xxdc00"}`},
		{"high_then_tab_escape_and_low_digits", `{"s":"\ud800\tdc00"}`},
		{"two_high_surrogates", `{"s":"\ud800\ud800"}`},
		{"pair_then_lone_low_escaped", esc(`{"s":"~ud83d~ude00~ude00"}`)},
		{"lone_surrogate_in_name", `{"\ud800":1}`},
		{"escaped_backslash_then_lone_surrogate", `{"s":"\\\ud800"}`},
		{"lone_surrogate_in_nested_string", `{"o":{"l":["\udfff"]}}`},
		{"invalid_hex_digit", `{"s":"\u12G4"}`},
		{"short_escape", `{"s":"\u12"}`},
	})
}

func TestParseObjectDecodesSurrogatePairs(t *testing.T) {
	for _, raw := range []string{
		esc(`{"s":"~ud83d~ude00"}`),
		esc(`{"s":"~uD83D~uDE00"}`),
		esc(`{"s":"~uD83d~udE00"}`),
	} {
		requireEscape(t, "surrogate_pair_escaped", raw)
		o, err := parseObject([]byte(raw))
		if err != nil {
			t.Fatalf("parseObject(%q) = %v", raw, err)
		}
		if s, _, err := o.str("s"); err != nil || s != "😀" {
			t.Fatalf("str(s) = %q, %v", s, err)
		}
	}
}

func TestParseObjectRejectsTrailingData(t *testing.T) {
	runRejectCases(t, []rejectCase{
		{"second_object", `{}{}`},
		{"second_object_after_space", `{} {}`},
		{"text", `{} x`},
		{"closing_bracket", `{}]`},
		{"closing_brace", `{}}`},
		{"comma", `{},`},
		{"null", `{}null`},
		{"number", `{} 1`},
		{"quote", `{}"`},
		{"nul_byte", "{}\x00"},
	})
}

// TestJSONDepthLimitMatchesPlan spells out the PLAN.md §4.4 nesting limit:
// the depth tests derive their inputs from maxJSONDepth, so they would pass
// with any value.
func TestJSONDepthLimitMatchesPlan(t *testing.T) {
	if maxJSONDepth != 16 {
		t.Fatalf("maxJSONDepth = %d, want 16", maxJSONDepth)
	}
}

func TestParseObjectDepthLimit(t *testing.T) {
	runRejectCases(t, []rejectCase{
		{"objects_over_limit", nestedObjects(maxJSONDepth + 1)},
		{"arrays_over_limit", nestedArrays(maxJSONDepth + 1)},
		{"far_over_limit", nestedArrays(10000)},
	})
}

func TestParseObjectRejectsNonObject(t *testing.T) {
	runRejectCases(t, []rejectCase{
		{"empty", ``},
		{"whitespace", " \n"},
		{"array", `[]`},
		{"array_of_object", `[{}]`},
		{"string", `"{}"`},
		{"number", `1`},
		{"null", `null`},
		{"bool", `true`},
		{"byte_order_mark", "\xef\xbb\xbf{}"},
	})
}

func TestParseObjectRejectsSyntaxErrors(t *testing.T) {
	runRejectCases(t, []rejectCase{
		{"unclosed", `{`},
		{"unclosed_member", `{"a":1`},
		{"closing_only", `}`},
		{"name_without_value", `{"a"}`},
		{"missing_value", `{"a":}`},
		{"missing_colon", `{"a" 1}`},
		{"missing_comma", `{"a":1 "b":2}`},
		{"unquoted_name", `{a:1}`},
		{"single_quotes", `{'a':1}`},
		{"trailing_comma", `{"a":1,}`},
		{"leading_comma", `{,"a":1}`},
		{"array_trailing_comma", `{"a":[1,]}`},
		{"mismatched_brackets", `{"a":[1}`},
		{"leading_zero", `{"a":01}`},
		{"nan", `{"a":NaN}`},
		{"bare_word", `{"a":tru}`},
		{"unterminated_string", `{"a":"x}`},
		{"control_character_in_string", "{\"a\":\"\x01\"}"},
		{"invalid_escape", `{"a":"\x"}`},
		{"comment", `{"a":1/*x*/}`},
	})
}

func TestObjectAccessors(t *testing.T) {
	o, err := parseObject([]byte(`{"s":"x","e":"","o":{"k":1},"a":[1,"x"],"n":null,"i":1,"b":true,"so":"{}","sa":"[]"}`))
	if err != nil {
		t.Fatal(err)
	}
	t.Run("str", func(t *testing.T) {
		if s, ok, err := o.str("s"); s != "x" || !ok || err != nil {
			t.Fatalf("str(s) = %q, %v, %v", s, ok, err)
		}
		if s, ok, err := o.str("e"); s != "" || !ok || err != nil {
			t.Fatalf("str(e) = %q, %v, %v", s, ok, err)
		}
		for _, name := range []string{"n", "i", "b", "o", "a"} {
			if _, ok, err := o.str(name); !ok || err == nil {
				t.Fatalf("str(%s) accepted a non-string", name)
			}
		}
	})
	t.Run("obj", func(t *testing.T) {
		if sub, ok, err := o.obj("o"); !ok || err != nil || string(sub["k"]) != "1" {
			t.Fatalf("obj(o) = %v, %v, %v", sub, ok, err)
		}
		for _, name := range []string{"n", "s", "so", "a", "i", "b"} {
			if _, ok, err := o.obj(name); !ok || err == nil {
				t.Fatalf("obj(%s) accepted a non-object", name)
			}
		}
	})
	t.Run("arr", func(t *testing.T) {
		if elems, ok, err := o.arr("a"); !ok || err != nil || len(elems) != 2 {
			t.Fatalf("arr(a) = %v, %v, %v", elems, ok, err)
		}
		for _, name := range []string{"n", "s", "sa", "o", "i", "b"} {
			if _, ok, err := o.arr(name); !ok || err == nil {
				t.Fatalf("arr(%s) accepted a non-array", name)
			}
		}
	})
	t.Run("absent_is_not_an_error", func(t *testing.T) {
		if _, ok, err := o.str("missing"); ok || err != nil {
			t.Fatal("str")
		}
		if _, ok, err := o.obj("missing"); ok || err != nil {
			t.Fatal("obj")
		}
		if _, ok, err := o.arr("missing"); ok || err != nil {
			t.Fatal("arr")
		}
	})
}

func TestArrayElementDecoders(t *testing.T) {
	if s, err := asString(json.RawMessage(`"x"`)); s != "x" || err != nil {
		t.Fatalf("asString = %q, %v", s, err)
	}
	if o, err := asObject(json.RawMessage(`{"k":1}`)); err != nil || string(o["k"]) != "1" {
		t.Fatalf("asObject = %v, %v", o, err)
	}
	for _, raw := range []string{``, `null`, `1`, `true`, `{}`, `[]`, `["x"]`} {
		if _, err := asString(json.RawMessage(raw)); err == nil {
			t.Fatalf("asString(%q) accepted a non-string", raw)
		}
	}
	for _, raw := range []string{``, `null`, `1`, `"{}"`, `[]`, `[{}]`} {
		if _, err := asObject(json.RawMessage(raw)); err == nil {
			t.Fatalf("asObject(%q) accepted a non-object", raw)
		}
	}
}
