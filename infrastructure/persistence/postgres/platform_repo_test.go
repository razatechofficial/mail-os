package postgres

// ADR 0001 rule A4: until the lockbox ships, the platform plane never
// returns tenant content. The platform read side reaches the database only
// through PlatformRepository; these tests pin what it may read, so a query
// that starts selecting a message's subject, recipients or body, an
// attachment, a template or a provider's configuration fails here first.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/razatechofficial/mail-os/application/platform"
)

// platformSQLIdentifiers are every table, alias, column and function the
// platform repository's SQL names: tenants (organizations) by id, state
// and creation time, and counts of their applications, sending domains
// and messages; the provider kinds in use. No content column is among
// them.
var platformSQLIdentifiers = []string{
	"a", "applications", "count", "created_at", "d", "deleted_at", "id", "is_active", "m", "messages",
	"o", "org_id", "organizations", "providers", "sending_domains", "timestamptz", "type",
}

var sqlKeywords = map[string]bool{
	"select": true, "from": true, "where": true, "and": true, "or": true, "is": true, "null": true, "not": true,
	"order": true, "by": true, "limit": true, "distinct": true,
}

var sqlIdentifier = regexp.MustCompile(`[a-z_][a-z0-9_]*`)

func TestPlatformRepositoryReadsNoTenantContent(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "platform_repo.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	queries := 0
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		s, err := strconv.Unquote(lit.Value)
		if err != nil || !strings.Contains(strings.ToUpper(s), "SELECT") {
			return true
		}
		queries++
		for _, id := range sqlIdentifier.FindAllString(strings.ToLower(s), -1) {
			if !sqlKeywords[id] {
				seen[id] = true
			}
		}
		return true
	})
	if queries != 2 {
		t.Fatalf("found %d queries in platform_repo.go, want 2: review a new query against ADR 0001 rule A4", queries)
	}
	var got []string
	for id := range seen {
		got = append(got, id)
	}
	sort.Strings(got)
	if !slices.Equal(got, platformSQLIdentifiers) {
		t.Fatalf("platform SQL names %v, pinned %v: a new table or column must be reviewed against ADR 0001 rule A4 "+
			"(no tenant content) before it is pinned here", got, platformSQLIdentifiers)
	}
}

// The platform read service can ask the database for these and nothing
// else.
func TestPlatformRepositoryMethodsArePinned(t *testing.T) {
	typ := reflect.TypeFor[platform.Repository]()
	var got []string
	for i := range typ.NumMethod() {
		got = append(got, typ.Method(i).Name)
	}
	want := []string{"ProviderKindsInUse", "TenantAggregates"}
	if !slices.Equal(got, want) {
		t.Fatalf("platform.Repository methods %v, want %v: review a new read against ADR 0001 rule A4 (no tenant content)", got, want)
	}
}
