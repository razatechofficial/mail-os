package redis

import (
	"context"
	"errors"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// zedTokenTTL outlives the longest platform role activation (8 h), so a
// person's newest token is kept while any write it covers can matter.
const zedTokenTTL = 24 * time.Hour

// ZedTokens keeps the newest ACS ZedToken of each platform account's
// relationships, shared by every MailOS replica (acs.Freshness).
type ZedTokens struct{ C *Client }

func zedTokenKey(subject string) string { return "mailos:acs:zedtoken:" + subject }

// Token is subject's newest token ("" when none is kept).
func (z ZedTokens) Token(ctx context.Context, subject string) (string, error) {
	tok, err := z.C.Get(ctx, zedTokenKey(subject)).Result()
	if errors.Is(err, goredis.Nil) {
		return "", nil
	}
	return tok, err
}

// Remember keeps token as subject's newest. Writes for one person come
// from the IAM's ordered delivery, one at a time, so the last write's token
// is the newest.
func (z ZedTokens) Remember(ctx context.Context, subject, token string) error {
	return z.C.Set(ctx, zedTokenKey(subject), token, zedTokenTTL).Err()
}
