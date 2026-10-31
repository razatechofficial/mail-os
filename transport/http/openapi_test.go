package http

import (
	"bytes"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode"

	"github.com/gin-gonic/gin"

	"github.com/razatechofficial/mail-os/config"
	"github.com/razatechofficial/mail-os/infrastructure/jwt"
	"github.com/razatechofficial/mail-os/pkg/logger"
	"github.com/razatechofficial/mail-os/transport/http/handler"
	"github.com/razatechofficial/mail-os/transport/http/middleware"
	"github.com/razatechofficial/mail-os/transport/http/openapi"
)

var updateOpenAPI = flag.Bool("update-openapi", false, "add stubs for undocumented /api/v1 routes to openapi/openapi.json and drop removed ones")

// allRoutes is every feature's route set with empty handlers: the test
// only reads the routes and probes them without credentials.
func allRoutes() []Routes {
	return []Routes{
		handler.NewTenantHandler(nil, nil, nil),
		handler.NewAuditLogHandler(nil),
		handler.NewTemplateHandler(nil, nil, handler.TemplateLimits{}),
		handler.NewEventHandler(nil),
		handler.NewContactHandler(nil),
		handler.NewContactListHandler(nil),
		handler.NewCampaignHandler(nil),
	}
}

// fullRouter mounts every route.
func fullRouter(t *testing.T) *gin.Engine {
	t.Helper()
	_ = logger.InitSimple("fatal", "console")
	cfg := &config.Config{}
	auth := &middleware.Auth{Verifier: jwt.NewVerifier(jwt.Config{Issuer: "http://127.0.0.1:9", Audience: "mailos"})}
	return NewRouter(cfg, Deps{Auth: auth}, allRoutes()...)
}

var ginParam = regexp.MustCompile(`[:*]([A-Za-z0-9_]+)`)

// openAPIPath turns /users/:id into /users/{id}.
func openAPIPath(p string) string { return ginParam.ReplaceAllString(p, "{$1}") }

// requiresAuth reports whether the route refuses an unauthenticated request
// with AuthRequired's 401.
func requiresAuth(r *gin.Engine, method, path string) bool {
	concrete := ginParam.ReplaceAllString(path, "00000000-0000-0000-0000-000000000001")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(method, concrete, nil))
	return w.Code == http.StatusUnauthorized && strings.Contains(w.Body.String(), middleware.MissingTokenMessage)
}

var handlerName = regexp.MustCompile(`\(\*(\w+)\)\.(\w+)`)

func humanize(s string) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 && unicode.IsUpper(r) {
			b.WriteByte(' ')
			r = unicode.ToLower(r)
		}
		b.WriteRune(r)
	}
	return b.String()
}

func stubOperation(rt gin.RouteInfo, path string, secured bool) map[string]any {
	summary := "Route"
	if m := handlerName.FindStringSubmatch(rt.Handler); m != nil {
		summary = humanize(m[2]) + " (" + strings.TrimSuffix(m[1], "Handler") + ")"
	}
	segs := strings.Split(strings.TrimPrefix(path, "/api/v1/"), "/")
	op := map[string]any{
		"operationId": strings.ToLower(rt.Method) + "_" + strings.Trim(regexp.MustCompile(`[^A-Za-z0-9]+`).ReplaceAllString(strings.TrimPrefix(path, "/api/v1/"), "_"), "_"),
		"summary":     summary,
		"tags":        []any{segs[0]},
		"x-stub":      true,
		"responses": map[string]any{
			"default": map[string]any{"$ref": "#/components/responses/Error"},
		},
	}
	if secured {
		op["security"] = []any{map[string]any{"bearer": []any{}}}
	} else {
		op["security"] = []any{}
	}
	var params []any
	for _, m := range ginParam.FindAllStringSubmatch(rt.Path, -1) {
		params = append(params, map[string]any{"name": m[1], "in": "path", "required": true, "schema": map[string]any{"type": "string"}})
	}
	if params != nil {
		op["parameters"] = params
	}
	return op
}

// TestOpenAPISpec keeps openapi.json and the router in step: every /api/v1
// route is documented with the authentication it really requires, and
// nothing documented is missing from the router.
func TestOpenAPISpec(t *testing.T) {
	r := fullRouter(t)
	specPath := filepath.Join("openapi", "openapi.json")
	raw, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, openapi.Spec()) {
		t.Fatal("embedded spec differs from the file; rebuild")
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("openapi.json: %v", err)
	}
	if doc["openapi"] != "3.1.0" {
		t.Fatalf("openapi = %v, want 3.1.0", doc["openapi"])
	}
	paths, _ := doc["paths"].(map[string]any)

	routes := map[string]gin.RouteInfo{}
	for _, rt := range r.Routes() {
		if strings.HasPrefix(rt.Path, "/api/v1/") {
			routes[strings.ToLower(rt.Method)+" "+openAPIPath(rt.Path)] = rt
		}
	}

	var problems []string
	changed := false
	for key, rt := range routes {
		method, path, _ := strings.Cut(key, " ")
		secured := requiresAuth(r, rt.Method, rt.Path)
		item, _ := paths[path].(map[string]any)
		op, _ := item[method].(map[string]any)
		if op == nil {
			if *updateOpenAPI {
				if item == nil {
					item = map[string]any{}
					paths[path] = item
				}
				item[method] = stubOperation(rt, path, secured)
				changed = true
				continue
			}
			problems = append(problems, "undocumented route "+strings.ToUpper(method)+" "+path)
			continue
		}
		sec, has := op["security"].([]any)
		if !has {
			problems = append(problems, key+": no security")
		} else if (len(sec) > 0) != secured {
			problems = append(problems, key+": security does not match the router (authenticated="+map[bool]string{true: "yes", false: "no"}[secured]+")")
		}
		declared := map[string]bool{}
		params, _ := op["parameters"].([]any)
		for _, p := range params {
			if pm, ok := p.(map[string]any); ok && pm["in"] == "path" {
				declared[pm["name"].(string)] = true
			}
		}
		for _, m := range ginParam.FindAllStringSubmatch(rt.Path, -1) {
			if !declared[m[1]] {
				problems = append(problems, key+": path parameter "+m[1]+" not declared")
			}
		}
		if resp, _ := op["responses"].(map[string]any); len(resp) == 0 {
			problems = append(problems, key+": no responses")
		}
	}
	seenIDs := map[string]string{}
	for path, v := range paths {
		item, _ := v.(map[string]any)
		for method, o := range item {
			key := method + " " + path
			if _, ok := routes[key]; !ok {
				if *updateOpenAPI {
					delete(item, method)
					changed = true
					continue
				}
				problems = append(problems, "documented route not in the router: "+strings.ToUpper(method)+" "+path)
			}
			if op, ok := o.(map[string]any); ok {
				id, _ := op["operationId"].(string)
				if prev, dup := seenIDs[id]; dup || id == "" {
					problems = append(problems, key+": operationId "+id+" missing or also used by "+prev)
				}
				seenIDs[id] = key
			}
		}
		if len(item) == 0 {
			delete(paths, path)
		}
	}
	// Every local $ref resolves.
	for _, ref := range regexp.MustCompile(`"\$ref":\s*"#/([^"]+)"`).FindAllStringSubmatch(string(raw), -1) {
		var node any = doc
		for _, part := range strings.Split(ref[1], "/") {
			m, _ := node.(map[string]any)
			node = m[part]
		}
		if node == nil {
			problems = append(problems, "unresolved $ref #/"+ref[1])
		}
	}

	if *updateOpenAPI && changed {
		out, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(specPath, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("openapi.json updated; describe the new x-stub operations")
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		t.Fatalf("openapi.json is out of step with the router (fix it, or run go test ./transport/http -run TestOpenAPISpec -update-openapi):\n  %s",
			strings.Join(problems, "\n  "))
	}
}

// The document is served unauthenticated at /api/v1/openapi.json.
func TestOpenAPIServed(t *testing.T) {
	r := fullRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil))
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("status %d type %q", w.Code, w.Header().Get("Content-Type"))
	}
	var doc map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil || doc["openapi"] != "3.1.0" {
		t.Fatalf("served document: %v %v", err, doc["openapi"])
	}
}
