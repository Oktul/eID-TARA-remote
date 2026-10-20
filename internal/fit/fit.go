// SPDX-License-Identifier: EUPL-1.2

// Package fit verifies Forge Invocation Tokens (FITs) and keeps the cache of
// Atlassian signing keys that verification depends on (PLAN.md §4.4, §4.5).
//
// The relay does the JWS mechanics itself with the standard library
// (PLAN.md D2). It accepts exactly one form, an RS256 compact JWS, so there
// is no algorithm negotiation for a caller to influence.
package fit

import "errors"

// Reason is a fixed classification of a FIT rejection. It is logged as
// auth_reason so an operator can see which check failed; the response never
// shows it (PLAN.md §4.4, §10). A Reason never carries token content.
type Reason string

// The rejection reasons. They are log values, not protocol: every one of
// them answers 401 invalid_token.
const (
	ReasonAuthorization Reason = "authorization"  // missing, repeated or malformed Bearer field
	ReasonTokenFormat   Reason = "token_format"   // size, parts, base64url or header JSON
	ReasonHeader        Reason = "header"         // alg, kid or a forbidden header member
	ReasonKeyUnknown    Reason = "key_unknown"    // no trusted key for the kid
	ReasonSignature     Reason = "signature"      // RS256 signature did not verify
	ReasonPayload       Reason = "payload"        // payload JSON or a required claim's shape
	ReasonIssuer        Reason = "issuer"         // iss
	ReasonAudience      Reason = "audience"       // aud
	ReasonDates         Reason = "dates"          // exp or nbf missing, malformed or out of range
	ReasonLifetime      Reason = "lifetime"       // exp - nbf over MaxLifetime
	ReasonExpired       Reason = "expired"        // now >= exp + skew
	ReasonNotYetValid   Reason = "not_yet_valid"  // now + skew < nbf
	ReasonEnvironment   Reason = "environment"    // app.environment.id
	ReasonCloudID       Reason = "cloud_id"       // site pin, D5
	ReasonInstallation  Reason = "installation"   // app.installationId pin
	ReasonIsolatedCloud Reason = "isolated_cloud" // icLabel present
)

// Error is a FIT rejection. Callers answer 401 invalid_token for every
// Error and log only its Reason.
type Error struct {
	Reason Reason
}

// Error returns "fit rejected: <reason>"; it never carries token content.
func (e *Error) Error() string { return "fit rejected: " + string(e.Reason) }

func reject(r Reason) error { return &Error{Reason: r} }

// ErrNotReady reports that no signing-key snapshot is usable: none has been
// loaded yet, or the last good one reached RELAY_JWKS_MAX_AGE. Callers answer
// 503 not_ready rather than 401, because the token was never judged
// (PLAN.md §4.2 step 1, §4.5).
var ErrNotReady = errors.New("fit: no usable signing-key snapshot")

// errKeyUnknown is returned by the key cache when a kid is still unknown
// after the bounded wait for a shared refresh (PLAN.md §4.5).
var errKeyUnknown = errors.New("fit: unknown key id")

// errJSON is the single error for every strict-JSON violation. Detail would
// only help an attacker probe the parser; the reason class is enough to log.
var errJSON = errors.New("fit: invalid json")
