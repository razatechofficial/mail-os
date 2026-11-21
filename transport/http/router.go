// Package http is the REST transport: the router, the server and its TLS,
// the OpenAPI document, and the handlers under handler/.
package http

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"

	"github.com/razatechofficial/mail-os/config"
	"github.com/razatechofficial/mail-os/transport/http/middleware"
	"github.com/razatechofficial/mail-os/transport/http/openapi"
)

// Routes is a feature's route set: each handler mounts its own routes on
// the authenticated /api/v1 group, guarding each with its permission.
type Routes interface {
	Mount(api *gin.RouterGroup, g middleware.Guard)
}

// PlatformRoutes are the platform API's route sets (ADR 0001 §3.1): each
// mounts its routes on the authenticated /api/platform/v1 group, guarding
// each with its ACS permission.
type PlatformRoutes interface {
	MountPlatform(api *gin.RouterGroup, g middleware.PlatformGuard)
}

// Route group prefixes. Each authenticated route is in exactly one: the
// tenant plane's or the platform plane's, each behind its own token rules.
const (
	TenantPrefix   = "/api/v1"
	PlatformPrefix = "/api/platform/v1"
)

// PublicRoutes are routes served without IAM authentication, outside
// the authenticated groups: each guards itself (provider webhook
// signatures, signed unsubscribe links, the IAM's signed role
// attestations).
type PublicRoutes interface {
	MountPublic(r gin.IRouter)
}

// Deps are what the router needs besides the feature routes.
type Deps struct {
	Auth    *middleware.Auth
	Guard   middleware.Guard
	Limiter middleware.WindowCounter
	// Ready reports whether the dependencies (Postgres, Redis) answer.
	Ready func(*gin.Context) error
	// Hooks are the test-only e2e routes (nil unless MAILOS_E2E_HOOKS).
	Hooks func(r *gin.Engine)
	// Public are the unauthenticated route sets.
	Public []PublicRoutes
	// PlatformAuth authenticates the platform API (platform tokens only);
	// PlatformGuard checks each platform route's permission in ACS.
	PlatformAuth  *middleware.PlatformAuth
	PlatformGuard middleware.PlatformGuard
	// Platform are the platform API's route sets.
	Platform []PlatformRoutes
}

// NewRouter builds the engine: global middleware, health, the OpenAPI
// document, then every feature's routes under /api/v1 behind tenant-plane
// authentication and the tenant rate limit, and the platform API under
// /api/platform/v1 behind platform authentication (ADR 0001 §3.3: a token
// accepted by one group is refused by the other).
func NewRouter(cfg *config.Config, d Deps, routes ...Routes) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if len(cfg.HTTP.TrustedProxies) > 0 {
		_ = r.SetTrustedProxies(cfg.HTTP.TrustedProxies)
	} else {
		_ = r.SetTrustedProxies(nil)
	}
	r.Use(middleware.Recovery(), middleware.RequestID(), middleware.Logger())
	if cfg.Telemetry.Enabled {
		r.Use(otelgin.Middleware(cfg.App.Name))
	}
	r.Use(middleware.SecurityHeaders(), middleware.CORS(cfg.CORS.Origins), middleware.BodyLimit(cfg.HTTP.BodyLimit()))

	r.GET("/health", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) })
	r.GET("/ready", func(c *gin.Context) {
		if d.Ready != nil {
			if err := d.Ready(c); err != nil {
				c.JSON(http.StatusServiceUnavailable, gin.H{"status": "unavailable"})
				return
			}
		}
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	})
	r.GET(TenantPrefix+"/openapi.json", func(c *gin.Context) { c.Data(http.StatusOK, "application/json", openapi.Spec()) })
	if d.Hooks != nil {
		d.Hooks(r)
	}
	for _, p := range d.Public {
		p.MountPublic(r)
	}

	api := r.Group(TenantPrefix, d.Auth.Required())
	if cfg.RateLimit.Enabled {
		api.Use(middleware.RateLimit(d.Limiter, "api", middleware.PerTenant, cfg.RateLimit.PerTenant+cfg.RateLimit.Burst, time.Second))
	}
	for _, rt := range routes {
		rt.Mount(api, d.Guard)
	}
	if d.PlatformAuth != nil {
		papi := r.Group(PlatformPrefix, d.PlatformAuth.Required())
		if cfg.RateLimit.Enabled {
			// A platform account has no tenant: the limit is per person.
			papi.Use(middleware.RateLimit(d.Limiter, "platform", middleware.PerUser, cfg.RateLimit.PerTenant+cfg.RateLimit.Burst, time.Second))
		}
		for _, rt := range d.Platform {
			rt.MountPlatform(papi, d.PlatformGuard)
		}
	}
	return r
}
