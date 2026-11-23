package acs_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/razatechofficial/mail-os/domain/platformrole"
	"github.com/razatechofficial/mail-os/infrastructure/acs"
	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

func TestPlatformRoles(t *testing.T) {
	f, c := newClient(t)
	p := acs.Platform{Client: c}
	ctx := context.Background()
	until := time.Now().Add(2 * time.Hour).Truncate(time.Second)

	if ok, err := p.Eligible(ctx, alice, platformrole.Operator); err != nil || ok {
		t.Fatalf("eligible before: %v %v", ok, err)
	}
	if err := p.AddEligibility(ctx, alice, platformrole.Operator); err != nil {
		t.Fatal(err)
	}
	if ok, err := p.Eligible(ctx, alice, platformrole.Operator); err != nil || !ok {
		t.Fatalf("eligible: %v %v", ok, err)
	}
	if ok, _ := p.Allowed(ctx, alice, platformrole.ViewTenants); ok {
		t.Fatal("eligibility alone grants")
	}
	if err := p.Activate(ctx, alice, platformrole.Operator, until, "jti-1"); err != nil {
		t.Fatal(err)
	}
	got, err := p.AllowedEach(ctx, alice, []platformrole.Permission{platformrole.ViewTenants, platformrole.ManageKeys, platformrole.StopSend})
	if err != nil || len(got) != 3 || !got[0] || got[1] || !got[2] {
		t.Fatalf("operator: %v %v", got, err)
	}
	active, eligible, err := p.Holdings(ctx, alice)
	if err != nil || len(active) != 1 || active[0].Role != platformrole.Operator || !active[0].ExpiresAt.Equal(until) ||
		len(eligible) != 1 || eligible[0] != platformrole.Operator {
		t.Fatalf("holdings: %+v %v %v", active, eligible, err)
	}
	if err := p.RemoveEligibility(ctx, alice, platformrole.Operator); err != nil {
		t.Fatal(err)
	}
	if ok, _ := p.Allowed(ctx, alice, platformrole.ViewTenants); ok {
		t.Fatal("removing the eligibility left the activation")
	}
	if rels := f.Relationships(); len(rels) != 0 {
		t.Fatalf("left behind: %v", rels)
	}

	// ACS refusing is a 400 with its reason; ACS down is a 503.
	err = p.Activate(ctx, alice, platformrole.Operator, time.Now().Add(9*time.Hour), "")
	if apperrors.KindOf(err) != apperrors.KindBadRequest {
		t.Fatalf("refused write: %v", err)
	}
	f.SetUnavailable(true)
	if _, err := p.Allowed(ctx, alice, platformrole.ViewTenants); apperrors.KindOf(err) != apperrors.KindUnavailable {
		t.Fatalf("down: %v", err)
	}
	if _, _, err := p.Holdings(ctx, alice); apperrors.KindOf(err) != apperrors.KindUnavailable {
		t.Fatalf("down: %v", err)
	}
}

type memTokens struct {
	m   map[string]string
	err error
}

func (t *memTokens) Token(_ context.Context, subject string) (string, error) {
	return t.m[subject], t.err
}
func (t *memTokens) Remember(_ context.Context, subject, token string) error {
	if t.err != nil {
		return t.err
	}
	t.m[subject] = token
	return nil
}

// Every check and read for a person asks ACS for data at least as fresh as
// that person's last write, so an ended role stops at once; a broken token
// store fails closed.
func TestPlatformReadsAtLeastAsFreshAsTheLastWrite(t *testing.T) {
	f, c := newClient(t)
	tokens := &memTokens{m: map[string]string{}}
	p := acs.Platform{Client: c, Tokens: tokens}
	ctx := context.Background()
	if err := p.AddEligibility(ctx, alice, platformrole.Operator); err != nil {
		t.Fatal(err)
	}
	if err := p.Activate(ctx, alice, platformrole.Operator, time.Now().Add(time.Hour), "jti-f"); err != nil {
		t.Fatal(err)
	}
	if err := p.End(ctx, alice, platformrole.Operator); err != nil {
		t.Fatal(err)
	}
	ended := tokens.m[alice]
	if ended == "" {
		t.Fatal("the write's token is not remembered")
	}
	before := len(f.Freshness())
	if ok, err := p.Allowed(ctx, alice, platformrole.ViewTenants); err != nil || ok {
		t.Fatalf("after end: %v %v", ok, err)
	}
	if _, err := p.AllowedEach(ctx, alice, []platformrole.Permission{platformrole.ViewTenants}); err != nil {
		t.Fatal(err)
	}
	if active, _, err := p.Holdings(ctx, alice); err != nil || len(active) != 0 {
		t.Fatalf("holdings after end: %v %v", active, err)
	}
	got := f.Freshness()[before:]
	if len(got) != 3 {
		t.Fatalf("calls %v", got)
	}
	for _, tok := range got {
		if tok != ended {
			t.Fatalf("a read asked for %q, not the end's token %q", tok, ended)
		}
	}
	if ok, _ := p.Allowed(ctx, "7b1e0c55-2f0d-4f43-9a3e-5d2c8e1f9b20", platformrole.ViewTenants); ok {
		t.Fatal("another person")
	}
	if tok := f.Freshness()[len(f.Freshness())-1]; tok != "" {
		t.Fatalf("a person with no write asks for %q", tok)
	}
	tokens.err = errors.New("redis down")
	if _, err := p.Allowed(ctx, alice, platformrole.ViewTenants); apperrors.KindOf(err) != apperrors.KindUnavailable {
		t.Fatalf("token store down: %v", err)
	}
}
