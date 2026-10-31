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

// Deps are what the router needs besides the feature routes.
type Deps struct {
	Auth    *middleware.Auth
	Guard   middleware.Guard
	Limiter middleware.WindowCounter
	// Ready reports whether the dependencies (Postgres, Redis) answer.
	Ready func(*gin.Context) error
	// Hooks are the test-only e2e routes (nil unless MAILOS_E2E_HOOKS).
	Hooks func(r *gin.Engine)
}

// NewRouter builds the engine: global middleware, health, the OpenAPI
// document, then every feature's routes under /api/v1 behind
// authentication and the tenant rate limit.
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
	r.GET("/api/v1/openapi.json", func(c *gin.Context) { c.Data(http.StatusOK, "application/json", openapi.Spec()) })
	if d.Hooks != nil {
		d.Hooks(r)
	}

	api := r.Group("/api/v1", d.Auth.Required())
	if cfg.RateLimit.Enabled {
		api.Use(middleware.RateLimit(d.Limiter, "api", middleware.PerTenant, cfg.RateLimit.PerTenant+cfg.RateLimit.Burst, time.Second))
	}
	for _, rt := range routes {
		rt.Mount(api, d.Guard)
	}
	return r
}
