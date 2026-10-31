package access

import (
	"errors"
	"slices"
	"testing"
	"time"
)

func TestRolePermissionsFollowContractTable(t *testing.T) {
	user := func(r ...Role) Principal { return Principal{Kind: KindUser, Roles: r} }
	cases := []struct {
		p     Principal
		perm  Permission
		allow bool
	}{
		{user(RoleViewer), PermTemplatesRead, true},
		{user(RoleViewer), PermMessagesRead, true},
		{user(RoleViewer), PermMessageBodies, false},
		{user(RoleViewer), PermAuditRead, false},
		{user(RoleTemplateEditor), PermTemplatesEdit, true},
		{user(RoleTemplateEditor), PermTemplatesPublish, false},
		{user(RoleTemplatePublisher), PermTemplatesPublish, true},
		{user(RoleTemplatePublisher), PermTemplatesEdit, false},
		{user(RoleOperator), PermMessagesOperate, true},
		{user(RoleOperator), PermProvidersManage, false},
		{user(RoleAuditor), PermAuditRead, true},
		{user(RoleAuditor), PermAuditExport, true},
		{user(RoleAuditor), PermMessagesOperate, false},
		{user(RoleAdmin), PermProvidersManage, true},
		{user(RoleAdmin), PermDomainsManage, true},
		{user(RoleAdmin), PermBrandingEdit, true},
		{user(RoleAdmin), PermRolesView, true},
		{user(), PermTemplatesRead, false},
		{Principal{Kind: KindService, ClientID: "iam"}, PermEventsDispatch, true},
		{Principal{Kind: KindService, ClientID: "iam", Roles: []Role{RoleAdmin}}, PermTemplatesRead, false},
		{user(RoleAdmin), PermEventsDispatch, false},
	}
	for _, c := range cases {
		if got := c.p.Can(c.perm); got != c.allow {
			t.Errorf("%v %v Can(%s) = %v, want %v", c.p.Kind, c.p.Roles, c.perm, got, c.allow)
		}
	}
	if !slices.Contains(PermissionsOf([]Role{RoleViewer, RoleTemplateEditor}), PermTemplatesEdit) {
		t.Fatal("permissions of several roles are not their union")
	}
}

func TestParseRoleIgnoresOtherIAMRoles(t *testing.T) {
	if _, ok := ParseRole("tenant_admin"); ok {
		t.Fatal("an IAM role that is not a MailOS role was accepted")
	}
	if r, ok := ParseRole(" mailos_operator "); !ok || r != RoleOperator {
		t.Fatalf("got %q %v", r, ok)
	}
}

func TestStepUpPolicy(t *testing.T) {
	now := time.Now()
	policy := StepUpPolicy{MaxAge: 5 * time.Minute, ACR: ACRMFA}
	fresh := Principal{Kind: KindUser, AuthTime: now.Add(-time.Minute), ACR: ACRMFA}
	if err := policy.Check(fresh, now); err != nil {
		t.Fatalf("fresh MFA sign-in refused: %v", err)
	}
	stale := fresh
	stale.AuthTime = now.Add(-6 * time.Minute)
	if err := policy.Check(stale, now); !errors.Is(err, ErrStepUpStale) {
		t.Fatalf("stale sign-in: %v", err)
	}
	noTime := fresh
	noTime.AuthTime = time.Time{}
	if err := policy.Check(noTime, now); !errors.Is(err, ErrStepUpStale) {
		t.Fatalf("missing auth_time: %v", err)
	}
	weak := fresh
	weak.ACR = ACRPassword
	if err := policy.Check(weak, now); !errors.Is(err, ErrStepUpWeak) {
		t.Fatalf("password-only sign-in: %v", err)
	}
	strong := fresh
	strong.ACR = ACRPhishingResistant
	if err := policy.Check(strong, now); err != nil {
		t.Fatalf("phishing-resistant sign-in refused: %v", err)
	}
	unknown := fresh
	unknown.ACR = "urn:other:gold"
	if err := policy.Check(unknown, now); !errors.Is(err, ErrStepUpWeak) {
		t.Fatalf("unknown acr: %v", err)
	}
	delegated := fresh
	delegated.Delegated = true
	if err := policy.Check(delegated, now); !errors.Is(err, ErrStepUpDelegated) {
		t.Fatalf("delegated token: %v", err)
	}
}

// A service may publish events and send; a spa browser user may only send
// to themselves, whatever roles its token carries.
func TestServiceAndSelfServicePermissions(t *testing.T) {
	svc := Principal{Kind: KindService, ClientID: "core"}
	for perm, want := range map[Permission]bool{
		PermEventsDispatch: true, PermMessagesSend: true, PermMessagesSendSelf: false,
		PermMessagesRead: false, PermApplicationsManage: false,
	} {
		if svc.Can(perm) != want {
			t.Errorf("service %s = %v", perm, !want)
		}
	}
	browser := Principal{Kind: KindUser, Roles: []Role{RoleAdmin}, SelfService: true, Scopes: []string{"mailos.send.self"}}
	if !browser.Can(PermMessagesSendSelf) || browser.Can(PermMessagesSend) || browser.Can(PermTemplatesRead) {
		t.Fatal("a self-service principal holds more than send_self")
	}
	if !browser.HasScope("mailos.send.self") || browser.HasScope("openid") {
		t.Fatal("HasScope")
	}
	admin := Principal{Kind: KindUser, Roles: []Role{RoleAdmin}}
	operator := Principal{Kind: KindUser, Roles: []Role{RoleOperator}}
	viewer := Principal{Kind: KindUser, Roles: []Role{RoleViewer}}
	if !admin.Can(PermApplicationsManage) || operator.Can(PermApplicationsManage) || !viewer.Can(PermApplicationsRead) {
		t.Fatal("applications permissions")
	}
	if !admin.Can(PermMessagesSend) || !operator.Can(PermMessagesSend) || viewer.Can(PermMessagesSend) {
		t.Fatal("send permission")
	}
	if !NeedsStepUp(PermApplicationsManage) || NeedsStepUp(PermApplicationsRead) {
		t.Fatal("step-up for applications")
	}
}
