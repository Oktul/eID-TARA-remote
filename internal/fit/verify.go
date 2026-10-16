// SPDX-License-Identifier: EUPL-1.2

package fit

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"slices"
	"time"
)

// Issuer is the only accepted iss claim (PLAN.md §4.4).
const Issuer = "forge/invocation-token"

// Policy is what a FIT must match: the relay's app, Forge environment and
// sites (PLAN.md §4.4, D5). An empty value never matches, so a zero Policy
// refuses every token.
type Policy struct {
	AppID           string        // RELAY_APP_ID, the expected aud
	EnvironmentID   string        // RELAY_ENVIRONMENT_ID
	CloudIDs        []string      // RELAY_CLOUD_IDS
	InstallationIDs []string      // RELAY_INSTALLATION_IDS; empty: no installation pin
	ClockSkew       time.Duration // RELAY_CLOCK_SKEW, the tolerance for exp and nbf
}

// Claims are what a verified FIT says about its caller.
type Claims struct {
	CloudID string // the pinned site; verified, so safe for the cloud_id log field (PLAN.md §10)
}

// keySource supplies trusted signing keys by key ID. *Cache is the
// production source; tests pass a fake. ErrNotReady means no usable snapshot
// exists; any other error means the key ID is unknown.
type keySource interface {
	Key(ctx context.Context, kid string) (*rsa.PublicKey, error)
}

// Verifier checks FITs against a Policy. It is safe for concurrent use.
type Verifier struct {
	policy Policy
	keys   keySource
	now    func() time.Time // time.Now; tests replace it
}

// NewVerifier returns a Verifier for p that takes signing keys from keys,
// normally the relay's *Cache.
func NewVerifier(p Policy, keys keySource) *Verifier {
	p.CloudIDs = slices.Clone(p.CloudIDs)
	p.InstallationIDs = slices.Clone(p.InstallationIDs)
	return &Verifier{policy: p, keys: keys, now: time.Now}
}

// Verify checks the Authorization field values of one request
// (r.Header.Values("Authorization"), so possibly none or several) and
// returns the verified claims. A rejection is an *Error, answered with
// 401 invalid_token; ErrNotReady means no usable key snapshot exists and is
// answered with 503 not_ready (PLAN.md §4.2, §4.3). Verify reports
// ErrNotReady only once a token reaches the key lookup, so callers check the
// cache's readiness first to keep the §4.2 order. ctx bounds the wait for an
// unknown key ID (PLAN.md §4.5).
func (v *Verifier) Verify(ctx context.Context, authorization []string) (Claims, error) {
	token, err := bearerToken(authorization)
	if err != nil {
		return Claims{}, err
	}
	t, err := parseCompact(token)
	if err != nil {
		return Claims{}, err
	}
	kid, err := checkHeader(t.header)
	if err != nil {
		return Claims{}, err
	}
	key, err := v.keys.Key(ctx, kid)
	if errors.Is(err, ErrNotReady) {
		return Claims{}, ErrNotReady
	}
	if err != nil || key == nil {
		return Claims{}, reject(ReasonKeyUnknown)
	}
	digest := sha256.Sum256([]byte(t.signingInput))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], t.signature) != nil {
		return Claims{}, reject(ReasonSignature)
	}
	// No claim is read before the signature over it has verified.
	raw, err := decodePart(t.payload)
	if err != nil {
		return Claims{}, reject(ReasonPayload)
	}
	payload, err := parseObject(raw)
	if err != nil {
		return Claims{}, reject(ReasonPayload)
	}
	return v.check(payload)
}

// check applies the claim rules of PLAN.md §4.4 in a fixed order, so the
// first failure decides the logged reason. Unknown claims are ignored
// (A-5).
func (v *Verifier) check(c object) (Claims, error) {
	// Isolated Cloud tokens are signed with keys from another JWKS, which the
	// relay does not trust; nothing else in one is read.
	if _, ok := c["icLabel"]; ok {
		return Claims{}, reject(ReasonIsolatedCloud)
	}
	if iss, ok, err := c.str("iss"); err != nil || !ok || iss != Issuer {
		return Claims{}, reject(ReasonIssuer)
	}
	if !v.audience(c) {
		return Claims{}, reject(ReasonAudience)
	}
	if err := v.dates(c); err != nil {
		return Claims{}, err
	}
	app, ok, err := c.obj("app")
	if err != nil || !ok {
		return Claims{}, reject(ReasonPayload)
	}
	if !v.environment(app) {
		return Claims{}, reject(ReasonEnvironment)
	}
	if err := v.installation(app); err != nil {
		return Claims{}, err
	}
	site, err := v.site(c, app)
	if err != nil {
		return Claims{}, err
	}
	return Claims{CloudID: site}, nil
}

// audience accepts aud as the app ID itself or as a non-empty array of
// non-empty strings that contains it (PLAN.md §4.4, A-3). The app ID is
// shared by every installation, which is why the site pin exists (D5).
func (v *Verifier) audience(c object) bool {
	want := v.policy.AppID
	raw := c["aud"]
	if want == "" || len(raw) == 0 {
		return false
	}
	switch raw[0] {
	case '"':
		aud, _, err := c.str("aud")
		return err == nil && aud == want
	case '[':
		// An empty array is refused because it cannot contain want.
		elems, _, err := c.arr("aud")
		if err != nil {
			return false
		}
		found := false
		for _, e := range elems {
			aud, err := asString(e)
			if err != nil || aud == "" {
				return false
			}
			found = found || aud == want
		}
		return found
	}
	return false
}

// dates checks exp and nbf (PLAN.md §4.4, A-4). parseNumericDate already
// rounded inexact values inward, so the comparisons below are exact.
func (v *Verifier) dates(c object) error {
	exp, err := parseNumericDate(c["exp"], false)
	if err != nil {
		return err
	}
	nbf, err := parseNumericDate(c["nbf"], true)
	if err != nil {
		return err
	}
	if !exp.After(nbf) {
		return reject(ReasonDates)
	}
	now, skew := v.now(), v.policy.ClockSkew
	if !now.Before(exp.Add(skew)) {
		return reject(ReasonExpired)
	}
	if now.Add(skew).Before(nbf) {
		return reject(ReasonNotYetValid)
	}
	return nil
}

// environment pins app.environment.id, so a token for another Forge
// environment of the same app is refused (PLAN.md §4.4, D5).
func (v *Verifier) environment(app object) bool {
	env, ok, err := app.obj("environment")
	if err != nil || !ok {
		return false
	}
	id, ok, err := env.str("id")
	return err == nil && ok && id != "" && id == v.policy.EnvironmentID
}

// installation applies the optional app.installationId pin. A supplied value
// must be a non-empty string even when no pin is configured (PLAN.md §4.4).
func (v *Verifier) installation(app object) error {
	id, ok, err := app.str("installationId")
	if err != nil || ok && id == "" {
		return reject(ReasonInstallation)
	}
	if len(v.policy.InstallationIDs) > 0 && !allowed(v.policy.InstallationIDs, id) {
		return reject(ReasonInstallation)
	}
	return nil
}

// site applies the site pin and returns the verified cloud ID (PLAN.md §4.4,
// D5). The signed context.cloudId decides alone; installation contexts may
// only confirm it. Phase 0 found it on this app's call path, so a token
// without it is refused rather than matched by its installation (§14).
// Malformed shapes are refused even where their value would not be used.
func (v *Verifier) site(c, app object) (string, error) {
	site, ok, err := invocationSite(c)
	if err != nil || !ok || !allowed(v.policy.CloudIDs, site) {
		return "", reject(ReasonCloudID)
	}
	sites, err := installationSites(app)
	if err != nil || len(sites) > 0 && !slices.Contains(sites, site) {
		return "", reject(ReasonCloudID)
	}
	return site, nil
}

// invocationSite returns context.cloudId. Both may be absent; a context that
// is not an object, or a cloudId that is not a string, is an error. An empty
// cloudId counts as present and then fails the allow-list in site.
func invocationSite(c object) (site string, present bool, err error) {
	inv, ok, err := c.obj("context")
	if err != nil || !ok {
		return "", false, err
	}
	return inv.str("cloudId")
}

// installationSites returns the cloud IDs named in app.installation.contexts.
// Each level may be absent; a present one must have the right shape.
func installationSites(app object) ([]string, error) {
	inst, ok, err := app.obj("installation")
	if err != nil || !ok {
		return nil, err
	}
	contexts, ok, err := inst.arr("contexts")
	if err != nil || !ok {
		return nil, err
	}
	var sites []string
	for _, raw := range contexts {
		entry, err := asObject(raw)
		if err != nil {
			return nil, err
		}
		site, ok, err := entry.str("cloudId")
		if err != nil || ok && site == "" {
			return nil, errJSON
		}
		if ok {
			sites = append(sites, site)
		}
	}
	return sites, nil
}

// allowed reports whether s is a non-empty member of list; an empty
// configured value can never be matched.
func allowed(list []string, s string) bool {
	return s != "" && slices.Contains(list, s)
}
