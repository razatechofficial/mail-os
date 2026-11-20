package message

import (
	"context"

	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// SentCheck is a VerifySent result: the evidence key that made the hashes,
// and whether each part of the copy matches what was sent.
type SentCheck struct {
	KeyID   string `json:"kid"`
	Subject bool   `json:"subject"`
	Text    bool   `json:"text"`
	HTML    bool   `json:"html"`
}

// Match reports whether every part matches.
func (c SentCheck) Match() bool { return c.Subject && c.Text && c.HTML }

// VerifySent checks a copy of a message (reconstructed from its template
// version and variables, with the secret the IAM recorded when the case
// needs it) against the hashes kept when it was sent. Only the key
// manager's evidence key can do this, so it is the custodian's check
// (mailos-verify-sent), never a console view.
func (s *Service) VerifySent(ctx context.Context, tenantID, messageID, subject, text, html string) (SentCheck, error) {
	m, err := s.d.Repo.Get(ctx, tenantID, messageID)
	if err != nil {
		return SentCheck{}, err
	}
	if m.SentDigest.IsZero() {
		return SentCheck{}, apperrors.Conflict("the message has no sent hash: it was not sent")
	}
	if s.d.Evidence == nil {
		return SentCheck{}, apperrors.Unavailable("the evidence key is not configured")
	}
	c := SentCheck{KeyID: m.SentDigest.KeyID}
	for _, p := range []struct {
		part, value string
		out         *bool
	}{{domainmsg.PartSubject, subject, &c.Subject}, {domainmsg.PartText, text, &c.Text}, {domainmsg.PartHTML, html, &c.HTML}} {
		if *p.out, err = m.SentDigest.VerifyPart(ctx, s.d.Evidence, p.part, p.value); err != nil {
			return SentCheck{}, err
		}
	}
	return c, nil
}
