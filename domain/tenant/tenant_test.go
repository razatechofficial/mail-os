package tenant

import "testing"

func TestRetentionBoundedAt90Days(t *testing.T) {
	for days, ok := range map[int]bool{1: true, 30: true, 90: true, 91: false, 3650: false, 0: false} {
		d := days
		if err := (Settings{MessageRetentionDays: &d}).Validate(); (err == nil) != ok {
			t.Errorf("%d days: %v", days, err)
		}
	}
	if err := (Settings{}).Validate(); err != nil {
		t.Fatal("platform default refused:", err)
	}
	d := 7
	if got := (Settings{MessageRetentionDays: &d}).RetentionDays(30); got != 7 {
		t.Fatalf("override %d", got)
	}
}
