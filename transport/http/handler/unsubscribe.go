package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/razatechofficial/mail-os/application/unsubscribe"
	"github.com/razatechofficial/mail-os/pkg/logger"
	"github.com/razatechofficial/mail-os/transport/http/middleware"
)

// UnsubscribeHandler is the public one-click unsubscribe endpoint (RFC
// 8058) that broadcast mail's List-Unsubscribe header points to. It takes
// no session: the signed token in the path is the authority.
//
//	GET  /unsubscribe/:token  a confirmation page; it never unsubscribes,
//	                          as mail scanners follow links
//	POST /unsubscribe/:token  List-Unsubscribe=One-Click (the mailbox
//	                          provider's one-click POST), or the page's form
type UnsubscribeHandler struct {
	svc     *unsubscribe.Service
	limiter middleware.WindowCounter
	rate    int
}

// NewUnsubscribeHandler builds the handler; limiter and rate bound requests
// per client address and minute (nil limiter: none).
func NewUnsubscribeHandler(svc *unsubscribe.Service, limiter middleware.WindowCounter, rate int) *UnsubscribeHandler {
	return &UnsubscribeHandler{svc: svc, limiter: limiter, rate: rate}
}

// MountPublic registers the routes outside /api/v1 and its authentication.
func (h *UnsubscribeHandler) MountPublic(r gin.IRouter) {
	g := r.Group("/unsubscribe", h.limit)
	g.GET("/:token", h.Page)
	g.POST("/:token", h.Unsubscribe)
}

// limit counts requests per client address; a counter that cannot answer
// lets the request through.
func (h *UnsubscribeHandler) limit(c *gin.Context) {
	if h.limiter == nil || h.rate <= 0 {
		c.Next()
		return
	}
	n, err := h.limiter.CountWindow(c.Request.Context(), "mailos:rl:unsubscribe:"+c.ClientIP(), time.Minute)
	if err != nil {
		logger.Warn("unsubscribe rate counter unavailable", logger.Err(err))
		c.Next()
		return
	}
	if n > int64(h.rate) {
		c.Header("Retry-After", "60")
		h.render(c, http.StatusTooManyRequests, pageData{Title: "Too many requests", Text: "Please try again in a minute."})
		c.Abort()
		return
	}
	c.Next()
}

// Page is GET /unsubscribe/:token: what the link does, and a button.
func (h *UnsubscribeHandler) Page(c *gin.Context) {
	claims, err := h.svc.Verify(c.Param("token"))
	if err != nil {
		h.invalid(c)
		return
	}
	h.render(c, http.StatusOK, pageData{Title: "Unsubscribe",
		Text:    "Stop sending marketing email to " + logger.MaskEmail(claims.Email) + "? Account and security messages still arrive.",
		Confirm: true})
}

// Unsubscribe is POST /unsubscribe/:token. The body is
// List-Unsubscribe=One-Click (RFC 8058 §3.2, urlencoded or multipart) or
// the confirmation form's confirm=yes; anything else is 400. A repeated
// request answers the same.
func (h *UnsubscribeHandler) Unsubscribe(c *gin.Context) {
	via := ""
	switch {
	case c.PostForm("List-Unsubscribe") == "One-Click":
		via = unsubscribe.ViaOneClick
	case c.PostForm("confirm") == "yes":
		via = unsubscribe.ViaPage
	default:
		h.render(c, http.StatusBadRequest, pageData{Title: "Unsubscribe", Text: "The request is not an unsubscribe request."})
		return
	}
	_, err := h.svc.Unsubscribe(c.Request.Context(), c.Param("token"), via)
	switch {
	case errors.Is(err, unsubscribe.ErrInvalidToken):
		h.invalid(c)
	case err != nil:
		logger.FromContext(c.Request.Context()).Error("unsubscribe not recorded", logger.Err(err))
		h.render(c, http.StatusServiceUnavailable, pageData{Title: "Unsubscribe", Text: "We could not record your request. Please try again later."})
	default:
		h.render(c, http.StatusOK, pageData{Title: "You are unsubscribed", Text: "You will no longer receive marketing email from this sender."})
	}
}

func (h *UnsubscribeHandler) invalid(c *gin.Context) {
	h.render(c, http.StatusBadRequest, pageData{Title: "Link not valid", Text: unsubscribe.ErrInvalidToken.Error() + "."})
}

type pageData struct {
	Title   string
	Text    string
	Confirm bool
}

const pageStyle = `body{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;color:#1f2937}button{font:inherit;padding:.5rem 1rem;cursor:pointer}`

var (
	pageTmpl = template.Must(template.New("unsubscribe").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>{{.Title}}</title><style>` + pageStyle + `</style></head>
<body><h1>{{.Title}}</h1><p>{{.Text}}</p>{{if .Confirm}}<form method="post"><input type="hidden" name="confirm" value="yes"><button type="submit">Unsubscribe</button></form>{{end}}</body></html>
`))
	// pageCSP allows the page's own style and a form posting back to itself.
	pageCSP = func() string {
		sum := sha256.Sum256([]byte(pageStyle))
		return "default-src 'none'; style-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) +
			"'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
	}()
)

func (h *UnsubscribeHandler) render(c *gin.Context, status int, d pageData) {
	var b strings.Builder
	if err := pageTmpl.Execute(&b, d); err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	c.Header("Content-Security-Policy", pageCSP)
	c.Data(status, "text/html; charset=utf-8", []byte(b.String()))
}
