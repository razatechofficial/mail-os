package template

import (
	"bytes"
	"slices"
	"time"

	apperrors "github.com/razatechofficial/mail-os/pkg/errors"
)

// VersionStatus is a version's state. Published versions never change.
type VersionStatus string

// Version states.
const (
	StatusPublished VersionStatus = "published"
)

// Version is a published copy of a draft (contract §6: published templates
// are immutable versions). Numbers run per template across locales; one
// version per locale is active, and sending uses it.
type Version struct {
	ID         string
	TemplateID string
	// Number is the API's "version": 1, 2, … per template.
	Number      int
	Locale      Locale
	Subject     string
	Preheader   string
	Design      []byte
	HTMLBody    string
	TextBody    string
	Variables   []string
	Status      VersionStatus
	IsActive    bool
	PublishedBy string
	PublishedAt time.Time
	CreatedAt   time.Time
}

// PublishRequest is a publish of one locale's draft.
type PublishRequest struct {
	// VersionID and Number are the new version's: a fresh ID and the
	// template's highest number plus one.
	VersionID string
	Number    int
	// Revision is the draft revision the publisher reviewed.
	Revision int
	// Publisher is the IAM user publishing.
	Publisher string
	// FourEyes is on when the tenant requires a second person to publish.
	FourEyes bool
	Now      time.Time
}

// CheckFourEyes refuses a publisher who saved the draft last when the
// tenant requires four-eyes (contract §5, separation of duties): 403
// FOUR_EYES_REQUIRED.
func CheckFourEyes(required bool, publisher, lastEditor string) error {
	if required && lastEditor != "" && publisher == lastEditor {
		return apperrors.NewAppError(apperrors.KindForbidden, apperrors.CodeFourEyesRequired,
			"four-eyes is on: someone other than the draft's last editor must publish it")
	}
	return nil
}

// Publish copies the draft into a new active version. It refuses, in
// order: no saved draft (422 no_draft), a revision other than the saved
// one (409), and the draft's last editor when four-eyes is on (403). The
// caller stores the version and deactivates the locale's previous one in
// the same transaction.
func (d Draft) Publish(r PublishRequest) (Version, error) {
	if d.Revision == 0 {
		return Version{}, apperrors.Invalid("locale", CodeNoDraft, "there is no saved draft in this locale to publish")
	}
	if err := CheckRevision(d.Revision, r.Revision); err != nil {
		return Version{}, err
	}
	if err := CheckFourEyes(r.FourEyes, r.Publisher, d.UpdatedBy); err != nil {
		return Version{}, err
	}
	return Version{
		ID:          r.VersionID,
		TemplateID:  d.TemplateID,
		Number:      r.Number,
		Locale:      d.Locale,
		Subject:     d.Subject,
		Preheader:   d.Preheader,
		Design:      bytes.Clone(d.Design),
		HTMLBody:    d.HTMLBody,
		TextBody:    d.TextBody,
		Variables:   slices.Clone(d.Variables),
		Status:      StatusPublished,
		IsActive:    true,
		PublishedBy: r.Publisher,
		PublishedAt: r.Now,
		CreatedAt:   r.Now,
	}, nil
}

// Restore replaces a draft with this version's content. current is the
// locale's draft (Revision 0 when none is saved) and revision the one the
// editor loaded. The restorer becomes the draft's last editor, so under
// four-eyes someone else publishes it.
func (v Version) Restore(current Draft, revision int, editor string, now time.Time) (Draft, error) {
	if current.Locale != v.Locale {
		return Draft{}, apperrors.Invalid("locale", CodeInvalid, "a version is restored into the draft of its own locale")
	}
	if err := CheckRevision(current.Revision, revision); err != nil {
		return Draft{}, err
	}
	return Draft{
		TemplateID: v.TemplateID,
		Locale:     v.Locale,
		Subject:    v.Subject,
		Preheader:  v.Preheader,
		Design:     bytes.Clone(v.Design),
		HTMLBody:   v.HTMLBody,
		TextBody:   v.TextBody,
		Variables:  slices.Clone(v.Variables),
		Revision:   current.Revision + 1,
		UpdatedBy:  editor,
		UpdatedAt:  now,
	}, nil
}

// SeedDraft is the draft offered when none is saved: revision 0, with the
// locale's active version's content and no design, or empty without one.
func SeedDraft(templateID string, locale Locale, active *Version) Draft {
	d := Draft{TemplateID: templateID, Locale: locale}
	if active != nil {
		d.Subject = active.Subject
		d.Preheader = active.Preheader
		d.HTMLBody = active.HTMLBody
		d.TextBody = active.TextBody
		d.Variables = slices.Clone(active.Variables)
	}
	return d
}
