package acs_test

import (
	"context"
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
