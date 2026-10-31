package mailer

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/razatechofficial/mail-os/domain/message"
	"github.com/razatechofficial/mail-os/domain/provider"
)

// e2eSinkKey is the Redis list the e2e sink writes to.
const e2eSinkKey = "mailos:e2e:captured"

// CapturedMail is one message the e2e sink kept, as the hook route serves it.
type CapturedMail struct {
	ID      string    `json:"id"`
	To      string    `json:"to"`
	From    string    `json:"from"`
	Subject string    `json:"subject"`
	HTML    string    `json:"html"`
	Text    string    `json:"text"`
	Tags    []string  `json:"tags"`
	SentAt  time.Time `json:"sent_at"`
}

// E2ESink is the platform sender of the black-box test run (MAILOS_E2E_HOOKS,
// refused outside test environments by config): it keeps mail in Redis, so
// the server's hook route can show what the worker process sent.
type E2ESink struct {
	rdb *goredis.Client
}

// NewE2ESink returns the sink.
func NewE2ESink(rdb *goredis.Client) *E2ESink { return &E2ESink{rdb: rdb} }

// Send records the message.
func (s *E2ESink) Send(ctx context.Context, out message.Outgoing) (Result, error) {
	if err := out.Validate(); err != nil {
		return Result{}, err
	}
	m := CapturedMail{ID: out.MessageID, To: out.To.Email, From: out.From.Email, Subject: out.Subject,
		HTML: out.HTML, Text: out.Text, Tags: append([]string{}, out.Tags...), SentAt: time.Now().UTC()}
	raw, err := json.Marshal(m)
	if err != nil {
		return Result{}, err
	}
	pipe := s.rdb.TxPipeline()
	pipe.RPush(ctx, e2eSinkKey, raw)
	pipe.LTrim(ctx, e2eSinkKey, -5000, -1)
	if _, err := pipe.Exec(ctx); err != nil {
		return Result{}, message.NewSendError("e2e", message.ReasonUnavailable, 0, err.Error())
	}
	return Result{ProviderMessageID: "e2e-" + out.MessageID, Kind: provider.Kind("e2e")}, nil
}

// List returns the kept mail to addr (all mail when addr is empty), oldest first.
func (s *E2ESink) List(ctx context.Context, addr string) ([]CapturedMail, error) {
	raws, err := s.rdb.LRange(ctx, e2eSinkKey, 0, -1).Result()
	if err != nil {
		return nil, err
	}
	out := []CapturedMail{}
	for _, r := range raws {
		var m CapturedMail
		if json.Unmarshal([]byte(r), &m) == nil && (addr == "" || strings.EqualFold(m.To, addr)) {
			out = append(out, m)
		}
	}
	return out, nil
}
