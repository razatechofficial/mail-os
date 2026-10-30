package template

import (
	"testing"
	"time"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

var publishedAt = time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC)

func savedDraft() Draft {
	d := validDraft()
	d.Revision = 3
	d.UpdatedBy = "editor-1"
	return d
}

func TestPublish(t *testing.T) {
	d := savedDraft()
	v, err := d.Publish(PublishRequest{VersionID: "v-4", Number: 4, Revision: 3, Publisher: "publisher-1", FourEyes: true, Now: publishedAt})
	if err != nil {
		t.Fatal(err)
	}
	if v.ID != "v-4" || v.Number != 4 || v.TemplateID != "t1" || v.Locale != LocaleEnglish || v.Status != StatusPublished ||
		!v.IsActive || v.PublishedBy != "publisher-1" || !v.PublishedAt.Equal(publishedAt) || v.Subject != d.Subject ||
		v.HTMLBody != d.HTMLBody || v.TextBody != d.TextBody || string(v.Design) != string(d.Design) {
		t.Fatalf("version = %+v", v)
	}
	// The version owns its content: editing the draft afterwards leaves it.
	d.Design[0] = 'X'
	d.Variables[0] = "changed"
	if v.Design[0] == 'X' || v.Variables[0] == "changed" {
		t.Fatal("version shares the draft's content")
	}
}

func TestPublish_refuses(t *testing.T) {
	unsaved := validDraft()
	_, err := unsaved.Publish(PublishRequest{Revision: 0, Publisher: "p"})
	if d := apperrors.DetailsOf(err); len(d) != 1 || d[0].Code != CodeNoDraft {
		t.Fatalf("unsaved draft: %v", err)
	}
	_, err = savedDraft().Publish(PublishRequest{Revision: 2, Publisher: "p"})
	if apperrors.Code(err) != apperrors.CodeConflict || apperrors.KindOf(err) != apperrors.KindConflict {
		t.Fatalf("stale revision: %v", err)
	}
	_, err = savedDraft().Publish(PublishRequest{Revision: 3, Publisher: "editor-1", FourEyes: true})
	if apperrors.Code(err) != apperrors.CodeFourEyesRequired || apperrors.KindOf(err) != apperrors.KindForbidden {
		t.Fatalf("own draft under four-eyes: %v", err)
	}
	if _, err := savedDraft().Publish(PublishRequest{Revision: 3, Publisher: "editor-1"}); err != nil {
		t.Fatalf("own draft without four-eyes: %v", err)
	}
	// Revision is checked before four-eyes: a stale page is reloaded first.
	_, err = savedDraft().Publish(PublishRequest{Revision: 1, Publisher: "editor-1", FourEyes: true})
	if apperrors.Code(err) != apperrors.CodeConflict {
		t.Fatalf("order: %v", err)
	}
}

func TestCheckFourEyes(t *testing.T) {
	if CheckFourEyes(true, "a", "b") != nil || CheckFourEyes(false, "a", "a") != nil || CheckFourEyes(true, "a", "") != nil {
		t.Fatal("refused")
	}
	if CheckFourEyes(true, "a", "a") == nil {
		t.Fatal("own draft allowed")
	}
}

func TestRestore(t *testing.T) {
	v, _ := savedDraft().Publish(PublishRequest{VersionID: "v-4", Number: 4, Revision: 3, Publisher: "p", Now: publishedAt})
	current := Draft{TemplateID: "t1", Locale: LocaleEnglish, Subject: "newer", Revision: 7, UpdatedBy: "x"}
	d, err := v.Restore(current, 7, "editor-2", publishedAt)
	if err != nil {
		t.Fatal(err)
	}
	if d.Revision != 8 || d.Subject != v.Subject || d.UpdatedBy != "editor-2" || string(d.Design) != string(v.Design) {
		t.Fatalf("restored = %+v", d)
	}
	if _, err := v.Restore(current, 6, "editor-2", publishedAt); apperrors.Code(err) != apperrors.CodeConflict {
		t.Fatalf("stale restore: %v", err)
	}
	if d, err := v.Restore(Draft{TemplateID: "t1", Locale: LocaleEnglish}, 0, "e", publishedAt); err != nil || d.Revision != 1 {
		t.Fatalf("restore with no draft: %+v %v", d, err)
	}
	if _, err := v.Restore(Draft{Locale: LocaleUrdu}, 0, "e", publishedAt); apperrors.KindOf(err) != apperrors.KindInvalidInput {
		t.Fatalf("restore into another locale: %v", err)
	}
}

func TestSeedDraft(t *testing.T) {
	if d := SeedDraft("t1", LocaleUrdu, nil); d.Revision != 0 || d.Locale != LocaleUrdu || d.Subject != "" {
		t.Fatalf("empty seed = %+v", d)
	}
	v, _ := savedDraft().Publish(PublishRequest{Revision: 3, Publisher: "p"})
	d := SeedDraft("t1", LocaleEnglish, &v)
	if d.Revision != 0 || d.Design != nil || d.Subject != v.Subject || d.HTMLBody != v.HTMLBody {
		t.Fatalf("seed = %+v", d)
	}
}
