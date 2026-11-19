package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/razatechofficial/mail-os/application/auditintegrity"
	"github.com/razatechofficial/mail-os/domain/access"
)

type fakeVerifier struct{ calls int }

func (f *fakeVerifier) Verify(context.Context) (*auditintegrity.Report, error) {
	f.calls++
	return &auditintegrity.Report{Digests: 2, Records: 7, Problems: []auditintegrity.Problem{}, Intact: true}, nil
}

func (f *fakeVerifier) PublicKey() auditintegrity.VerificationKey {
	return auditintegrity.VerificationKey{ID: "k1", PublicKey: "cHVi"}
}

func (f *fakeVerifier) PreviousKeys() []auditintegrity.VerificationKey { return nil }

// The digests cover every tenant, so only the operator tenant's auditors
// verify them, and each verification is audited.
func TestAuditIntegrityIsTheOperatorAuditorsOnly(t *testing.T) {
	const path = "/api/v1/analytics/audit-logs/integrity"
	for _, operator := range []string{"", "0192f0c4-0000-7000-8000-0000000000ff"} {
		v := &fakeVerifier{}
		r := engine(t, NewAuditIntegrityHandler(v, &recAudit{}, operator), []access.Role{access.RoleAuditor}, 0, access.ACRMFA)
		if w := do(r, http.MethodGet, path, nil); w.Code != http.StatusForbidden || v.calls != 0 {
			t.Fatalf("operator %q: %d", operator, w.Code)
		}
	}
	v, a := &fakeVerifier{}, &recAudit{}
	viewer := engine(t, NewAuditIntegrityHandler(v, a, testTenant), []access.Role{access.RoleViewer}, 0, access.ACRMFA)
	if w := do(viewer, http.MethodGet, path, nil); w.Code != http.StatusForbidden {
		t.Fatalf("viewer: %d", w.Code)
	}
	auditor := engine(t, NewAuditIntegrityHandler(v, a, testTenant), []access.Role{access.RoleAuditor}, 0, access.ACRMFA)
	w := do(auditor, http.MethodGet, path, nil)
	var body struct {
		Data struct {
			Intact     bool                           `json:"intact"`
			Digests    int                            `json:"digests_checked"`
			SigningKey auditintegrity.VerificationKey `json:"signing_key"`
		} `json:"data"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &body) != nil || !body.Data.Intact || body.Data.Digests != 2 ||
		body.Data.SigningKey.ID != "k1" {
		t.Fatalf("auditor: %d %s", w.Code, w.Body.String())
	}
	if len(a.actions) != 1 || a.actions[0] != "audit.verified" {
		t.Fatalf("audit %v", a.actions)
	}
}
