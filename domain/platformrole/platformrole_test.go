package platformrole

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// The table here and authz/module.zed say the same thing: every role is an
// expiring relation with an eligibility twin, and every permission is the
// union of exactly the roles the table lists.
func TestPermissionsMatchModule(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "authz", "module.zed"))
	if err != nil {
		t.Fatal(err)
	}
	zed := string(raw)
	for _, r := range Roles {
		if !regexp.MustCompile(`(?m)^\s*relation ` + r.Relation() + `: user with expiration$`).MatchString(zed) {
			t.Errorf("module.zed: %s is not an expiring user relation", r)
		}
		if !regexp.MustCompile(`(?m)^\s*relation ` + r.EligibleRelation() + `: user$`).MatchString(zed) {
			t.Errorf("module.zed: %s is not a plain user relation", r.EligibleRelation())
		}
	}
	defined := map[string][]Role{}
	for _, m := range regexp.MustCompile(`(?m)^\s*permission (\w+) = (.+)$`).FindAllStringSubmatch(zed, -1) {
		var roles []Role
		for _, term := range strings.Split(m[2], "+") {
			r, ok := Parse(strings.TrimSpace(term))
			if !ok {
				t.Errorf("module.zed: permission %s uses %q, not an activation relation", m[1], strings.TrimSpace(term))
			}
			roles = append(roles, r)
		}
		defined[m[1]] = roles
	}
	if len(defined) != len(Permissions) {
		t.Errorf("module.zed defines %d permissions, the table %d", len(defined), len(Permissions))
	}
	for _, p := range Permissions {
		got := defined[string(p.Permission)]
		want := slices.Clone(p.Roles)
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s: module.zed %v, table %v", p.Permission, got, want)
		}
	}
}

// Contract C5: owner, template publisher and key custodian 4 h with a
// second approver; the others 8 h; none past ACS's 8 h horizon.
func TestMaxActivation(t *testing.T) {
	for _, r := range Roles {
		want := 8 * time.Hour
		if r == Owner || r == TemplatePublisher || r == KeyCustodian {
			want = 4 * time.Hour
		}
		if r.MaxActivation() != want || r.MaxActivation() > MaxActivationCeiling || r.NeedsSecondApprover() != (want == 4*time.Hour) {
			t.Errorf("%s: %s", r, r.MaxActivation())
		}
	}
}

func TestRoleOfRelation(t *testing.T) {
	if r, el, ok := RoleOfRelation("eligible_platform_support"); !ok || !el || r != Support {
		t.Fatal(r, el, ok)
	}
	if r, el, ok := RoleOfRelation("platform_auditor"); !ok || el || r != Auditor {
		t.Fatal(r, el, ok)
	}
	for _, bad := range []string{"eligible_", "platform", "eligible_mailos_admin", "viewer"} {
		if _, _, ok := RoleOfRelation(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}

// No role reaches content (templates), keys and logs (audit) together.
func TestNoRoleSpansContentKeysAndLogs(t *testing.T) {
	content := []Permission{ViewTemplates, EditTemplates, PublishTemplates}
	logs := []Permission{ViewAudit, VerifyAudit, ExportAudit}
	any := func(r Role, ps []Permission) bool {
		return slices.ContainsFunc(ps, func(p Permission) bool { return Grants([]Role{r}, p) })
	}
	for _, r := range Roles {
		if any(r, content) && Grants([]Role{r}, ManageKeys) && any(r, logs) {
			t.Errorf("%s reaches content, keys and logs", r)
		}
	}
}
