package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"

	"github.com/razatechofficial/mail-os/pkg/logger"
)

// Store persists events. With stream set it also queues the event in the
// outbox in the same transaction, so the relay publishes exactly what was
// committed (IAM's audit_kafka_outbox pattern).
type Store interface {
	Insert(ctx context.Context, ev Event, stream bool) error
}

// Writer is the application-facing audit writer.
type Writer struct {
	store  Store
	stream bool
}

// NewWriter builds the writer. stream is FEATURE_AUDIT_STREAM.
func NewWriter(store Store, stream bool) *Writer {
	return &Writer{store: store, stream: stream}
}

// Append records action on a resource. Actor, tenant and request come from
// ctx. A failure is returned: a change whose audit row cannot be written
// should not be reported as done.
func (w *Writer) Append(ctx context.Context, resourceType, resourceID, action string, metadata map[string]any) error {
	ev := NewEvent(ctx, resourceType, resourceID, action, metadata)
	return w.write(ctx, ev)
}

// Change records a configuration change with its before and after values,
// keeping only the fields that changed. Secret fields are marked as changed
// but written as [REDACTED] (PCI DSS 10.2.1.7, contract §6).
func (w *Writer) Change(ctx context.Context, resourceType, resourceID, action string, before, after any, extra map[string]any) error {
	b, a := toMap(before), toMap(after)
	changed := diff(b, a)
	meta := map[string]any{}
	for k, v := range extra {
		meta[k] = v
	}
	if len(changed) > 0 {
		meta["changed"] = changed
	}
	if b != nil {
		meta["before"] = pick(b, changed)
	}
	if a != nil {
		meta["after"] = pick(a, changed)
	}
	return w.write(ctx, NewEvent(ctx, resourceType, resourceID, action, meta))
}

func (w *Writer) write(ctx context.Context, ev Event) error {
	if w == nil {
		return nil
	}
	logger.FromContext(ctx).Info("audit",
		logger.String("log_category", logger.CategoryAudit),
		logger.String("action", ev.Action),
		logger.String("resource_type", ev.ResourceType),
		logger.String("resource_id", ev.ResourceID),
		logger.String("severity", ev.Severity.String()),
	)
	if w.store == nil {
		return nil
	}
	if err := w.store.Insert(ctx, ev, w.stream); err != nil {
		logger.FromContext(ctx).Error("audit insert failed", logger.String("action", ev.Action), logger.Err(err))
		return fmt.Errorf("audit: %w", err)
	}
	return nil
}

// RedactedValue replaces secret values in before/after records.
const RedactedValue = "[REDACTED]"

// secretFields are written as RedactedValue whatever their value.
var secretFields = map[string]bool{
	"credentials": true, "password": true, "secret": true, "api_key": true, "token": true,
	"dkim_private_key": true, "private_key": true, "client_secret": true, "access_key_id": true,
	"secret_access_key": true, "webhook_secret": true, "signing_secret": true,
}

// IsSecretField reports whether a record field holds a secret.
func IsSecretField(name string) bool {
	return secretFields[name] || logger.IsSecretFieldKey(name)
}

func toMap(v any) map[string]any {
	if v == nil || (reflect.ValueOf(v).Kind() == reflect.Pointer && reflect.ValueOf(v).IsNil()) {
		return nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	return m
}

func diff(before, after map[string]any) []string {
	keys := map[string]bool{}
	for k := range before {
		keys[k] = true
	}
	for k := range after {
		keys[k] = true
	}
	var out []string
	for k := range keys {
		if k == "updated_at" || k == "created_at" {
			continue
		}
		if !reflect.DeepEqual(before[k], after[k]) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func pick(m map[string]any, keys []string) map[string]any {
	out := make(map[string]any, len(keys))
	for _, k := range keys {
		v, ok := m[k]
		if !ok {
			continue
		}
		if IsSecretField(k) && v != nil && v != "" {
			v = RedactedValue
		}
		out[k] = v
	}
	return out
}
