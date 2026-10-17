// SPDX-License-Identifier: EUPL-1.2

package config

// The parsers behind Load, for the fuzz tests in package config_test. Only
// test builds compile this file.
var ParseCAs = parseCAs

// SplitList is loader.list with the error it keeps.
func SplitList(name, s string) ([]string, error) {
	l := &loader{}
	items := l.list(name, s)
	return items, l.err
}
