// SPDX-License-Identifier: EUPL-1.2

package config

// The parsers behind Load, for the fuzz tests in package config_test. Only
// test builds compile this file.
var (
	SplitList   = splitList
	ParseCAs    = parseCAs
	ParseDigits = parseDigits
)
