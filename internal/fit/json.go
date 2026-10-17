// SPDX-License-Identifier: EUPL-1.2

package fit

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"unicode/utf8"
)

// maxJSONDepth bounds nesting in FIT headers, payloads and the JWKS. A FIT
// payload nests five levels (an app.installation.contexts entry), a header
// one and the JWKS three; the bound keeps the duplicate-name walk below cheap
// on hostile input.
const maxJSONDepth = 16

// object is one decoded JSON object. Its member names are exact: map lookup
// is case-sensitive, whereas encoding/json struct decoding would let "ISS"
// satisfy "iss" (PLAN.md §4.4).
type object map[string]json.RawMessage

// parseObject accepts raw only if it is exactly one JSON object in valid
// UTF-8, with no invalid Unicode escape, no duplicate member name at any
// nesting level and nothing after it (PLAN.md §4.4). encoding/json alone
// would silently replace invalid UTF-8 and lone surrogates with U+FFFD, keep
// the last of duplicate names and ignore case, so each of those is checked
// here first.
func parseObject(raw []byte) (object, error) {
	if !utf8.Valid(raw) || !validEscapes(raw) {
		return nil, errJSON
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, errJSON
	}
	if err := walk(dec, '{', 1); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errJSON
	}
	var o object
	if err := json.Unmarshal(raw, &o); err != nil {
		return nil, errJSON
	}
	return o, nil
}

// walk consumes the members of the object or array whose opening delimiter
// was just read, rejecting duplicate names. Token returns decoded names, so
// "\u0069ss" and "iss" count as the same name (PLAN.md §4.4).
func walk(dec *json.Decoder, open json.Delim, depth int) error {
	if depth > maxJSONDepth {
		return errJSON
	}
	var seen map[string]bool
	if open == '{' {
		seen = make(map[string]bool)
	}
	for dec.More() {
		if seen != nil {
			tok, err := dec.Token()
			if err != nil {
				return errJSON
			}
			name, ok := tok.(string)
			if !ok || seen[name] {
				return errJSON
			}
			seen[name] = true
		}
		tok, err := dec.Token()
		if err != nil {
			return errJSON
		}
		if d, ok := tok.(json.Delim); ok {
			if err := walk(dec, d, depth+1); err != nil {
				return err
			}
		}
	}
	want := json.Delim('}')
	if open == '[' {
		want = ']'
	}
	if tok, err := dec.Token(); err != nil || tok != want {
		return errJSON
	}
	return nil
}

// validEscapes reports whether every \u escape in raw's strings is a valid
// Unicode scalar value: a high surrogate must be followed by an escaped low
// surrogate, and a low surrogate may not stand alone. Other syntax errors are
// left to the decoder.
func validEscapes(raw []byte) bool {
	inString := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if !inString {
			inString = c == '"'
			continue
		}
		switch c {
		case '"':
			inString = false
		case '\\':
			if i+1 >= len(raw) {
				return false
			}
			if raw[i+1] != 'u' {
				i++
				continue
			}
			r, ok := hex4(raw, i+2)
			if !ok {
				return false
			}
			i += 5
			switch {
			case r >= 0xDC00 && r <= 0xDFFF:
				return false
			case r >= 0xD800 && r <= 0xDBFF:
				if i+2 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
					return false
				}
				lo, ok := hex4(raw, i+3)
				if !ok || lo < 0xDC00 || lo > 0xDFFF {
					return false
				}
				i += 6
			}
		}
	}
	return true
}

// hex4 decodes the four hexadecimal digits of a \u escape starting at raw[i].
func hex4(raw []byte, i int) (rune, bool) {
	if i+4 > len(raw) {
		return 0, false
	}
	n, err := strconv.ParseUint(string(raw[i:i+4]), 16, 16)
	return rune(n), err == nil
}

// str returns member name as a string. A missing member gives present ==
// false; a present member that is not a JSON string, including null, is an
// error, so absence and wrong types can never be confused.
func (o object) str(name string) (s string, present bool, err error) {
	raw, ok := o[name]
	if !ok {
		return "", false, nil
	}
	s, err = asString(raw)
	return s, true, err
}

// obj returns member name as an object, with the same rules as str.
func (o object) obj(name string) (sub object, present bool, err error) {
	raw, ok := o[name]
	if !ok {
		return nil, false, nil
	}
	sub, err = asObject(raw)
	return sub, true, err
}

// arr returns member name as the raw elements of an array, with the same
// rules as str.
func (o object) arr(name string) (elems []json.RawMessage, present bool, err error) {
	raw, ok := o[name]
	if !ok {
		return nil, false, nil
	}
	if len(raw) == 0 || raw[0] != '[' {
		return nil, true, errJSON
	}
	if err := json.Unmarshal(raw, &elems); err != nil {
		return nil, true, errJSON
	}
	return elems, true, nil
}

// asString decodes a raw member or array element that must be a JSON string;
// null and every other type are errors.
func asString(raw json.RawMessage) (string, error) {
	var s string
	if len(raw) == 0 || raw[0] != '"' {
		return "", errJSON
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", errJSON
	}
	return s, nil
}

// asObject decodes a raw member or array element that must be a JSON object,
// with the same rules as asString.
func asObject(raw json.RawMessage) (object, error) {
	var o object
	if len(raw) == 0 || raw[0] != '{' {
		return nil, errJSON
	}
	if err := json.Unmarshal(raw, &o); err != nil {
		return nil, errJSON
	}
	return o, nil
}
