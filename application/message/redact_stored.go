package message

import (
	"context"

	domainmsg "github.com/razatechofficial/mail-os/domain/message"
	domaintemplate "github.com/razatechofficial/mail-os/domain/template"
)

// StoredMail reads and rewrites stored messages for RedactStored.
type StoredMail interface {
	// AuthMessagesAfter lists up to limit messages of every tenant whose
	// topic is one of topics and whose body was not purged, with id above
	// afterID, in id order.
	AuthMessagesAfter(ctx context.Context, topics []string, afterID string, limit int) ([]domainmsg.Message, error)
	// SaveRedacted stores m's subject, bodies, template data and last
	// error.
	SaveRedacted(ctx context.Context, m domainmsg.Message) error
}

// RedactReport counts a RedactStored run: the authentication-class
// messages read, and those that still held a live secret and were
// redacted.
type RedactReport struct {
	Scanned  int `json:"scanned"`
	Redacted int `json:"redacted"`
}

// AuthTopics lists the authentication-class topics of the catalogue.
func AuthTopics() []string {
	var out []string
	for _, t := range domaintemplate.Topics() {
		if t.AuthClass {
			out = append(out, t.Key)
		}
	}
	return out
}

// RedactStored redacts authentication mail stored before persistence
// masking: in every such message whose body is still stored, each secret
// value of its template data becomes its redaction descriptor, and every
// occurrence of the value in the subject, the bodies and the last error is
// replaced. A message already redacted holds descriptors only and is left
// as it is, so a second run changes nothing. A message still waiting to be
// sent has no sealed secrets and fails with SecretExpired when the worker
// reaches it. Nothing it handles is logged.
func RedactStored(ctx context.Context, store StoredMail, batch int) (RedactReport, error) {
	if batch <= 0 {
		batch = 500
	}
	topics := AuthTopics()
	var rep RedactReport
	after := ""
	for {
		list, err := store.AuthMessagesAfter(ctx, topics, after, batch)
		if err != nil {
			return rep, err
		}
		for _, m := range list {
			rep.Scanned++
			after = m.ID
			stored, live := domainmsg.SplitSecrets(m.Topic, m.TemplateData)
			if len(live) == 0 {
				continue
			}
			m.TemplateData = stored
			m.Subject, m.HTMLBody, m.TextBody = live.Scrub(m.Subject), live.Scrub(m.HTMLBody), live.Scrub(m.TextBody)
			m.LastError = live.Scrub(m.LastError)
			if err := store.SaveRedacted(ctx, m); err != nil {
				return rep, err
			}
			rep.Redacted++
		}
		if len(list) < batch {
			return rep, nil
		}
	}
}
