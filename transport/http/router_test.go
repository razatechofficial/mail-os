package http

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/razatechofficial/mail-os/config"
	"github.com/razatechofficial/mail-os/domain/access"
	"github.com/razatechofficial/mail-os/pkg/logger"
	"github.com/razatechofficial/mail-os/transport/http/handler"
	"github.com/razatechofficial/mail-os/transport/http/middleware"
)

// planeVerifier stands in for the JWT verifier: "tenant" is a tenant
// administrator's token, "platform" a platform account's; each plane's
// method accepts only its own, as the real verifier does.
type planeVerifier struct{}

var errRefused = errors.New("refused")

func (planeVerifier) Principal(_ context.Context, raw string) (access.Principal, error) {
	if raw != "tenant" {
		return access.Principal{}, errRefused
	}
	return access.Principal{Kind: access.KindUser, Subject: "u", TenantID: "6f1c3c3e-6a38-4a8f-9a59-2b9d3b6a8a10", Roles: access.Roles}, nil
}

func (planeVerifier) PlatformPrincipal(_ context.Context, raw string) (access.Principal, error) {
	if raw != "platform" {
		return access.Principal{}, errRefused
	}
	return access.Principal{Kind: access.KindPlatform, Subject: "0d6f3a7e-5b1c-4c55-9f61-2f8f1c9b6a11"}, nil
}

type okTenants struct{}

func (okTenants) Ensure(context.Context, string) error { return nil }

// allPlatformRoutes is every platform route set with empty services.
func allPlatformRoutes() []PlatformRoutes {
	return []PlatformRoutes{handler.NewPlatformHandler(nil, nil)}
}

// allPublicRoutes are the unauthenticated route sets the tests mount.
func allPublicRoutes() []PublicRoutes {
	return []PublicRoutes{handler.NewPlatformRolesHandler(nil)}
}

func planesRouter(t *testing.T) *gin.Engine {
	t.Helper()
	_ = logger.InitSimple("fatal", "console")
	v := planeVerifier{}
	return NewRouter(&config.Config{}, Deps{
		Auth:         &middleware.Auth{Verifier: v, Tenants: okTenants{}},
		PlatformAuth: &middleware.PlatformAuth{Verifier: v},
		Platform:     allPlatformRoutes(),
		Public:       allPublicRoutes(),
	}, allRoutes()...)
}

func authenticatedWith(r *gin.Engine, method, path, token string) bool {
	concrete := ginParam.ReplaceAllString(path, "00000000-0000-0000-0000-000000000001")
	req := httptest.NewRequest(method, concrete, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code != http.StatusUnauthorized
}

// Every authenticated route is in exactly one group (ADR 0001 §3.3): a
// /api/v1 route passes a tenant token and refuses a platform token, an
// /api/platform/v1 route the reverse, and the only unauthenticated route
// under the platform prefix is the IAM's attestation delivery.
func TestEachRouteInExactlyOneGroup(t *testing.T) {
	r := planesRouter(t)
	var tenant, platform int
	for _, rt := range r.Routes() {
		tenantOK := authenticatedWith(r, rt.Method, rt.Path, "tenant")
		platformOK := authenticatedWith(r, rt.Method, rt.Path, "platform")
		anonymous := authenticatedWith(r, rt.Method, rt.Path, "")
		switch {
		case rt.Path == handler.RoleAttestationsPath:
			if !anonymous {
				t.Errorf("%s %s needs a bearer token", rt.Method, rt.Path)
			}
		case rt.Path == TenantPrefix+"/openapi.json":
		case strings.HasPrefix(rt.Path, TenantPrefix+"/"):
			tenant++
			if !tenantOK || platformOK || anonymous {
				t.Errorf("tenant route %s %s: tenant %v platform %v anonymous %v", rt.Method, rt.Path, tenantOK, platformOK, anonymous)
			}
		case strings.HasPrefix(rt.Path, PlatformPrefix+"/"):
			platform++
			if !platformOK || tenantOK || anonymous {
				t.Errorf("platform route %s %s: tenant %v platform %v anonymous %v", rt.Method, rt.Path, tenantOK, platformOK, anonymous)
			}
		default:
			if !anonymous {
				t.Errorf("route %s %s is authenticated outside both groups", rt.Method, rt.Path)
			}
		}
	}
	if tenant < 50 || platform != 5 {
		t.Fatalf("mounted %d tenant and %d platform routes", tenant, platform)
	}
}
