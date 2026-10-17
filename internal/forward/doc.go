// SPDX-License-Identifier: EUPL-1.2

// Package forward is the relay's only path to the upstream (PLAN.md §5).
//
// It validates the upstream origin and credential (PLAN.md §8), then sends
// POST /oidc/token with the fixed header allowlists of PLAN.md §5. Its
// client follows no redirects, never decompresses, speaks only
// HTTP/1.1 over TLS 1.2 or later and never replays a token exchange
// (PLAN.md §5, R-8).
//
// The package answers nothing itself. Forward returns the complete upstream
// answer or one of four fixed errors, and the server turns them into the
// responses of PLAN.md §4.3.
package forward
