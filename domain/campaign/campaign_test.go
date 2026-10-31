package campaign

import (
	"strings"
	"testing"
	"time"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

var now = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

func valid() *Campaign {
	return &Campaign{Name: " Launch ", Subject: "Hello", FromName: "Averox", FromEmail: "news@example.com",
		TemplateID: "t1", ContactListID: "l1", Status: StatusDraft}
}

func TestCheck(t *testing.T) {
	c := valid()
	if err := c.Check(); err != nil || c.Name != "Launch" || c.Type != TypeRegular || c.Metadata == nil {
		t.Fatalf("%+v %v", c, err)
	}
	bad := &Campaign{Subject: "a\r\nBcc: x@example.com", FromEmail: "News <news@example.com>", Type: TypeABTest}
	got := map[string]string{}
	for _, d := range apperrors.DetailsOf(bad.Check()) {
		got[d.Field] = d.Code
	}
	want := map[string]string{"name": "required", "subject": "invalid", "from_name": "required", "from_email": "invalid",
		"template_id": "required", "contact_list_id": "required", "type": "unsupported"}
	for f, code := range want {
		if got[f] != code {
			t.Fatalf("%s: got %v", f, got)
		}
	}
	long := valid()
	long.Subject = strings.Repeat("s", MaxSubjectLen+1)
	if apperrors.KindOf(long.Check()) != apperrors.KindInvalidInput {
		t.Fatal("long subject accepted")
	}
}

func TestLaunchNowAndScheduled(t *testing.T) {
	c := valid()
	if sending, err := c.Launch(now); err != nil || !sending || c.Status != StatusSending || !c.StartedAt.Equal(now) {
		t.Fatalf("launch now: %v %v %+v", sending, err, c)
	}
	future := now.Add(time.Hour)
	c = valid()
	c.ScheduledAt = &future
	if sending, err := c.Launch(now); err != nil || sending || c.Status != StatusScheduled || c.StartedAt != nil {
		t.Fatalf("launch scheduled: %v %v %+v", sending, err, c)
	}
	if err := c.Release(now); apperrors.KindOf(err) != apperrors.KindConflict {
		t.Fatalf("released early: %v", err)
	}
	if err := c.Release(future); err != nil || c.Status != StatusSending {
		t.Fatalf("release: %v %s", err, c.Status)
	}
	c = valid()
	c.ScheduledAt = &future
	_, _ = c.Launch(now)
	if sending, err := c.Launch(now); err != nil || !sending {
		t.Fatalf("launching a scheduled campaign sends now: %v %v", sending, err)
	}
	past := now.Add(-time.Minute)
	c = valid()
	c.ScheduledAt = &past
	if sending, _ := c.Launch(now); !sending {
		t.Fatal("past schedule waits")
	}
}

func TestTransitions(t *testing.T) {
	c := valid()
	if err := c.Pause(now); apperrors.KindOf(err) != apperrors.KindConflict {
		t.Fatal("paused a draft")
	}
	_, _ = c.Launch(now)
	if err := c.Editable(); err == nil {
		t.Fatal("edited while sending")
	}
	if err := c.Deletable(); err == nil {
		t.Fatal("deleted while sending")
	}
	if _, err := c.Launch(now); apperrors.KindOf(err) != apperrors.KindConflict {
		t.Fatal("launched twice")
	}
	if err := c.Pause(now); err != nil || c.Status != StatusPaused {
		t.Fatal(err)
	}
	if err := c.Deletable(); err != nil {
		t.Fatal("paused campaign not deletable")
	}
	if err := c.Resume(now); err != nil || c.Status != StatusSending {
		t.Fatal(err)
	}
	if err := c.Complete(now); err != nil || c.Status != StatusCompleted || c.CompletedAt == nil {
		t.Fatal(err)
	}
	if err := c.Cancel(now); apperrors.KindOf(err) != apperrors.KindConflict {
		t.Fatal("cancelled a completed campaign")
	}
	c = valid()
	if err := c.Cancel(now); err != nil || c.Status != StatusCancelled {
		t.Fatal(err)
	}
	if err := c.Resume(now); err == nil || !strings.Contains(err.Error(), "cancelled campaign cannot be resumed") {
		t.Fatalf("resume cancelled: %v", err)
	}
}
