package audit

import "strings"

// Severity is a syslog severity (RFC 5424 §6.2.1): 0 is the most severe.
type Severity int

// The eight syslog severities.
const (
	SeverityEmergency     Severity = 0 // system is unusable
	SeverityAlert         Severity = 1 // action must be taken immediately
	SeverityCritical      Severity = 2 // critical conditions
	SeverityError         Severity = 3 // error conditions
	SeverityWarning       Severity = 4 // warning conditions
	SeverityNotice        Severity = 5 // normal but significant condition
	SeverityInformational Severity = 6 // informational messages
	SeverityDebug         Severity = 7 // debug-level messages
)

var severityNames = [...]string{
	"emergency", "alert", "critical", "error", "warning", "notice", "informational", "debug",
}

// String returns the lower-case RFC 5424 name ("warning").
func (s Severity) String() string {
	if s < 0 || int(s) >= len(severityNames) {
		return "unknown"
	}
	return severityNames[s]
}

// alertActions need someone to act now: a replayed or forged signature on
// IAM's pub/sub stream means someone is injecting messages.
var alertActions = map[string]struct{}{
	"encryption_key.compromised": {},
}

// rejectionAlertReasons are the mailos.message_rejected reasons that mean
// an attack rather than a misconfiguration.
var rejectionAlertReasons = map[string]struct{}{
	"bad_signature": {},
	"replayed":      {},
	"body_mismatch": {},
}

// SeverityOfAction maps an audit action to a syslog severity, with the same
// rules as IAM's (infrastructure/audit/severity.go there):
//
//   - Emergency and Debug are never assigned.
//   - Alert: a key declared compromised.
//   - Error: an operation that failed for a system reason (*_error, *.failed
//     for deliveries is Warning instead).
//   - Warning: refused or failed requests (*_denied, *_refused, *.rejected,
//     access_denied, step_up_required, mailos.message_rejected).
//   - Notice: administrative and security changes (critical tier,
//     *.created/updated/deleted/rotated, publishing, reading or exporting
//     message bodies or the audit log, key events, purges).
//   - Informational: everything else (messages accepted and sent).
func SeverityOfAction(action, tier string) Severity {
	a := strings.ToLower(strings.TrimSpace(action))
	if _, ok := alertActions[a]; ok {
		return SeverityAlert
	}
	if hasAnySuffix(a, "_error", ".error") {
		return SeverityError
	}
	if a == "access_denied" || a == "step_up_required" || a == "mailos.message_rejected" || a == "event.refused" ||
		hasAnySuffix(a, "_failed", ".failed", "_denied", ".denied", "_refused", ".refused", ".rejected", "_blocked") {
		return SeverityWarning
	}
	if tier == TierCritical || isChangeAction(a) || strings.HasPrefix(a, "audit_log.") ||
		strings.HasPrefix(a, "encryption_key.") {
		return SeverityNotice
	}
	return SeverityInformational
}

// SeverityOf is SeverityOfAction for an event, raising a message rejection
// that signals an attack (forged, replayed or tampered message) to Alert.
func SeverityOf(ev Event) Severity {
	if ev.Action == "mailos.message_rejected" {
		if r, _ := ev.Metadata["reason"].(string); r != "" {
			if _, ok := rejectionAlertReasons[r]; ok {
				return SeverityAlert
			}
		}
	}
	return SeverityOfAction(ev.Action, ev.Tier)
}

// isChangeAction reports configuration changes ("provider.updated").
func isChangeAction(a string) bool {
	return hasAnySuffix(a, ".created", ".updated", ".deleted", ".rotated", ".published", ".restored")
}

func hasAnySuffix(s string, suffixes ...string) bool {
	for _, x := range suffixes {
		if strings.HasSuffix(s, x) {
			return true
		}
	}
	return false
}
