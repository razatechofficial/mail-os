package smtp

import (
	"bytes"
	"encoding/json"
	"strings"

	gosmtp "github.com/emersion/go-smtp"
)

// SASL mechanisms (RFC 4954 AUTH).
const (
	MechOAuthBearer = "OAUTHBEARER" // RFC 7628
	MechXOAuth2     = "XOAUTH2"     // the Google and Microsoft profile
	MechPlain       = "PLAIN"       // RFC 4616
	MechLogin       = "LOGIN"       // draft-murchison-sasl-login, what legacy clients send
)

// Bounds of what a client may send in an exchange.
const (
	maxUsername = 256
	maxPassword = 1024
	maxToken    = 16 << 10
)

// Replies of an exchange. A failed authentication is always 535 5.7.8,
// whatever the reason (RFC 4954 §6): the reason is audited, never sent.
var (
	errAuthFailed = &gosmtp.SMTPError{Code: 535, EnhancedCode: gosmtp.EnhancedCode{5, 7, 8}, Message: "Authentication credentials invalid"}
	errAuthSyntax = &gosmtp.SMTPError{Code: 501, EnhancedCode: gosmtp.EnhancedCode{5, 5, 2}, Message: "Malformed authentication response"}
	errAuthTemp   = &gosmtp.SMTPError{Code: 454, EnhancedCode: gosmtp.EnhancedCode{4, 7, 0}, Message: "Temporary authentication failure, try again later"}
)

// passwordCheck decides a username and password; it returns one of the
// errors above.
type passwordCheck func(username, password string) error

// tokenCheck decides a bearer token; it returns one of the errors above.
type tokenCheck func(token string) error

// plainServer is PLAIN: authzid NUL authcid NUL password. An authorization
// identity other than the username is refused: one credential acts as one
// application only.
type plainServer struct {
	check passwordCheck
	done  bool
}

func (s *plainServer) Next(resp []byte) ([]byte, bool, error) {
	if s.done {
		return nil, true, errAuthSyntax
	}
	if resp == nil {
		return []byte{}, false, nil
	}
	s.done = true
	parts := bytes.Split(resp, []byte{0})
	if len(parts) != 3 {
		return nil, true, errAuthSyntax
	}
	authz, user, pass := string(parts[0]), string(parts[1]), string(parts[2])
	if len(user) > maxUsername || len(pass) > maxPassword || (authz != "" && authz != user) {
		return nil, true, errAuthFailed
	}
	return nil, true, s.check(user, pass)
}

// loginServer is LOGIN: the username and the password each answer a
// challenge; the username may come as the initial response.
type loginServer struct {
	check passwordCheck
	step  int
	user  string
}

func (s *loginServer) Next(resp []byte) ([]byte, bool, error) {
	switch s.step {
	case 0:
		s.step = 1
		if resp == nil {
			return []byte("Username:"), false, nil
		}
		fallthrough
	case 1:
		if len(resp) > maxUsername {
			return nil, true, errAuthFailed
		}
		s.user, s.step = string(resp), 2
		return []byte("Password:"), false, nil
	case 2:
		s.step = 3
		if len(resp) > maxPassword {
			return nil, true, errAuthFailed
		}
		return nil, true, s.check(s.user, string(resp))
	}
	return nil, true, errAuthSyntax
}

// bearerServer is OAUTHBEARER and XOAUTH2. Both carry "auth=Bearer
// <token>" among ^A-separated fields; OAUTHBEARER starts with a GS2
// header ("n,a=<authzid>,"). A refusal is a JSON error challenge the
// client answers (^A for OAUTHBEARER, an empty line for XOAUTH2) before the
// 535 (RFC 7628 §3.2.3).
type bearerServer struct {
	mech   string
	check  tokenCheck
	step   int
	failed error
}

func (s *bearerServer) Next(resp []byte) ([]byte, bool, error) {
	switch s.step {
	case 0:
		if resp == nil {
			s.step = 1
			return []byte{}, false, nil
		}
		fallthrough
	case 1:
		s.step = 2
		token, ok := s.token(resp)
		if !ok {
			return nil, true, errAuthSyntax
		}
		err := s.check(token)
		if err != errAuthFailed {
			return nil, true, err // success, or a temporary failure
		}
		s.failed = err
		status := "invalid_token"
		if s.mech == MechXOAuth2 {
			status = "401"
		}
		blob, _ := json.Marshal(map[string]string{"status": status, "schemes": "bearer", "scope": "mailos"})
		return blob, false, nil
	case 2:
		s.step = 3
		return nil, true, s.failed
	}
	return nil, true, errAuthSyntax
}

// token extracts the bearer token of an initial client response.
func (s *bearerServer) token(resp []byte) (string, bool) {
	if len(resp) > maxToken {
		return "", false
	}
	fields := string(resp)
	if s.mech == MechOAuthBearer {
		// gs2-header: "n," [ "a=" authzid ] ","; channel binding is not
		// offered, so "y" and "p" are refused.
		gs2, rest, ok := strings.Cut(fields, ",")
		if !ok || gs2 != "n" {
			return "", false
		}
		if _, rest, ok = strings.Cut(rest, ","); !ok {
			return "", false
		}
		fields = rest
	}
	for _, f := range strings.Split(fields, "\x01") {
		k, v, ok := strings.Cut(f, "=")
		if !ok || k != "auth" {
			continue
		}
		scheme, token, ok := strings.Cut(v, " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
			return "", false
		}
		return strings.TrimSpace(token), true
	}
	return "", false
}
