package container

import (
	"context"
	"fmt"

	"github.com/razatechofficial/mail-os/application/platform"
	"github.com/razatechofficial/mail-os/application/platformroles"
	"github.com/razatechofficial/mail-os/domain/access"
	"github.com/razatechofficial/mail-os/infrastructure/acs"
	"github.com/razatechofficial/mail-os/infrastructure/cache/redis"
	"github.com/razatechofficial/mail-os/infrastructure/jwt"
	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
	"github.com/razatechofficial/mail-os/pkg/logger"
	"github.com/razatechofficial/mail-os/transport/http/handler"
	"github.com/razatechofficial/mail-os/transport/http/middleware"
)

// approvalJWKSPath is where the IAM publishes its ACS approval keys.
const approvalJWKSPath = "/.well-known/acs-approval-jwks.json"

// buildPlatform wires the platform API (/api/platform/v1, ADR 0001 §3.1):
// platform-token authentication, the ACS guard, the read routes, and the
// IAM's role attestation delivery. Without ACS_ENDPOINT the routes are
// mounted but answer 503: nothing on the platform plane is decided without
// ACS.
func (c *Container) buildPlatform(context.Context) error {
	cfg := c.Cfg
	// Contract C2: only the platform console's tokens, from a passkey
	// sign-in no older than the platform session.
	signIn := access.PlatformSignIn{ClientIDs: cfg.Platform.AllowedClients(), MaxAge: cfg.Platform.MaxAge}
	c.PlatformAuth = &middleware.PlatformAuth{Verifier: c.Verifier, SignIn: signIn, DPoP: c.Auth.DPoP, TrustForwarded: c.Auth.TrustForwarded}
	reads := platform.New(postgres.NewPlatformRepository(c.DB), c.Platform != nil)
	if !cfg.ACS.Enabled() {
		logger.Warn("ACS_ENDPOINT is not set: the platform API answers 503")
		c.PlatformRoutes = append(c.PlatformRoutes, handler.NewPlatformHandler(reads, nil))
		c.PublicRoutes = append(c.PublicRoutes, handler.NewPlatformRolesHandler(nil))
		return nil
	}
	client, err := acs.Dial(acs.Config{Endpoint: cfg.ACS.Endpoint, ServerName: cfg.ACS.ServerName, CAFile: cfg.ACS.CAFile,
		CertFile: cfg.ACS.CertFile, KeyFile: cfg.ACS.KeyFile, TokenURL: cfg.ACS.TokenURL, ClientID: cfg.ACS.ClientID,
		Insecure: cfg.ACS.Insecure, Timeout: cfg.ACS.Timeout})
	if err != nil {
		return fmt.Errorf("acs: %w", err)
	}
	c.closers = append(c.closers, func() { _ = client.Close() })
	roles := acs.Platform{Client: client, Tokens: redis.ZedTokens{C: c.Redis}}
	c.PlatformGuard = middleware.PlatformGuard{ACS: roles, Audit: c.Audit}
	approvals := jwt.NewVerifier(jwt.Config{Issuer: cfg.IAM.Issuer, JWKSURL: c.Verifier.Issuer() + approvalJWKSPath,
		CacheTTL: cfg.IAM.JWKSCacheTTL, ClockSkew: cfg.IAM.ClockSkew, HTTPClient: c.iamHTTP})
	c.PlatformRoutes = append(c.PlatformRoutes, handler.NewPlatformHandler(reads, roles))
	c.PublicRoutes = append(c.PublicRoutes, handler.NewPlatformRolesHandler(platformroles.New(approvals, roles, c.Redis, c.Audit)))
	return nil
}
