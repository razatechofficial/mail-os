package logger

// Log category values for downstream routing (Loki labels / retention policies).
const (
	CategorySecurity = "security"
	CategoryAudit    = "audit"
)

func withCategory(category string, fields []Field) []Field {
	return append([]Field{String("log_category", category)}, fields...)
}

// SecurityInfo logs a security-relevant informational event (never volume-sampled).
func SecurityInfo(msg string, fields ...Field) {
	criticalLog().Info(msg, withCategory(CategorySecurity, fields)...)
}

// SecurityWarn logs a security-relevant warning (failed login, lockout, rate limit).
func SecurityWarn(msg string, fields ...Field) {
	criticalLog().Warn(msg, withCategory(CategorySecurity, fields)...)
}

// SecurityError logs a security incident (privilege escalation, policy violation).
func SecurityError(msg string, fields ...Field) {
	criticalLog().Error(msg, withCategory(CategorySecurity, fields)...)
}

// AuditInfo logs an immutable audit event (never volume-sampled).
func AuditInfo(msg string, fields ...Field) {
	criticalLog().Info(msg, withCategory(CategoryAudit, fields)...)
}

// AuditWarn logs a sensitive audit event (permission change, password change, user delete).
func AuditWarn(msg string, fields ...Field) {
	criticalLog().Warn(msg, withCategory(CategoryAudit, fields)...)
}
