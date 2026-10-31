package contact

import (
	"strings"
	"testing"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

func fields(err error) map[string]string {
	out := map[string]string{}
	for _, d := range apperrors.DetailsOf(err) {
		out[d.Field] = d.Code
	}
	return out
}

func TestCheckNormalizes(t *testing.T) {
	c := Contact{Email: "  Amna.Khan@Example.COM ", FirstName: " Amna ", LastName: "Khan"}
	if err := c.Check(); err != nil {
		t.Fatal(err)
	}
	if c.Email != "amna.khan@example.com" || c.FirstName != "Amna" || c.Status != StatusActive || c.Metadata == nil {
		t.Fatalf("normalized %+v", c)
	}
}

func TestCheckRefuses(t *testing.T) {
	c := Contact{Email: "Amna <amna@example.com>", FirstName: "a\nb", LastName: strings.Repeat("x", 256), Status: "gone",
		Metadata: map[string]any{"blob": strings.Repeat("x", MaxMetadataBytes)}}
	err := c.Check()
	if apperrors.KindOf(err) != apperrors.KindInvalidInput {
		t.Fatalf("kind %v", err)
	}
	want := map[string]string{"email": "invalid", "first_name": "invalid", "last_name": "invalid", "status": "invalid", "metadata": "too_large"}
	if got := fields(err); len(got) != len(want) {
		t.Fatalf("fields %v", got)
	}
	for f, code := range want {
		if fields(err)[f] != code {
			t.Fatalf("%s: %v", f, fields(err))
		}
	}
	if strings.Contains(err.Error(), "amna@") || strings.Contains(apperrors.UserMessage(err), "amna@") {
		t.Fatal("address quoted in the error")
	}
	if got := fields((&Contact{}).Check()); got["email"] != "required" {
		t.Fatalf("empty: %v", got)
	}
}

func TestCheckBatch(t *testing.T) {
	out, dup, err := CheckBatch([]Contact{{Email: "a@example.com"}, {Email: "A@example.com "}, {Email: "b@example.com"}})
	if err != nil || len(out) != 2 || dup != 1 {
		t.Fatalf("batch %v %d %v", out, dup, err)
	}
	_, _, err = CheckBatch([]Contact{{Email: "a@example.com"}, {Email: "nope"}})
	if fields(err)["contacts[1].email"] != "invalid" {
		t.Fatalf("indexed field: %v", fields(err))
	}
	if _, _, err := CheckBatch(nil); fields(err)["contacts"] != "required" {
		t.Fatal("empty import accepted")
	}
	if _, _, err := CheckBatch(make([]Contact, MaxBatch+1)); fields(err)["contacts"] != "too_many" {
		t.Fatal("oversized import accepted")
	}
}

func TestChanges(t *testing.T) {
	a := Contact{Email: "a@example.com", FirstName: "A", Status: StatusActive, Metadata: map[string]any{"k": 1}}
	b := a
	b.Status, b.Metadata = StatusUnsubscribed, map[string]any{"k": 2}
	if got := Changes(a, b); strings.Join(got, ",") != "status,metadata" {
		t.Fatalf("changes %v", got)
	}
	if got := Changes(a, a); got != nil {
		t.Fatalf("no change: %v", got)
	}
}

func TestListCheck(t *testing.T) {
	l := List{Name: " VIP "}
	if err := l.Check(); err != nil || l.Name != "VIP" || l.Type != ListStatic {
		t.Fatalf("%+v %v", l, err)
	}
	if got := fields((&List{Name: "x", Type: ListDynamic, Query: "status = active"}).Check()); got["type"] != "unsupported" {
		t.Fatalf("dynamic: %v", got)
	}
	got := fields((&List{Type: "smart", Query: "q", Description: strings.Repeat("d", MaxDescriptionLen+1)}).Check())
	if got["name"] != "required" || got["type"] != "invalid" || got["description"] != "too_long" {
		t.Fatalf("invalid list: %v", got)
	}
	if got := fields((&List{Name: "x", Query: "q"}).Check()); got["query"] != "not_allowed" {
		t.Fatalf("static with query: %v", got)
	}
}

func TestCheckMembers(t *testing.T) {
	ids, err := CheckMembers([]string{" c1 ", "c2", "c1", ""})
	if err != nil || strings.Join(ids, ",") != "c1,c2" {
		t.Fatalf("%v %v", ids, err)
	}
	if _, err := CheckMembers([]string{" "}); fields(err)["contact_ids"] != "required" {
		t.Fatal("empty accepted")
	}
	many := make([]string, MaxMembersPerCall+1)
	for i := range many {
		many[i] = strings.Repeat("x", i+1)
	}
	if _, err := CheckMembers(many); fields(err)["contact_ids"] != "too_many" {
		t.Fatal("too many accepted")
	}
}
