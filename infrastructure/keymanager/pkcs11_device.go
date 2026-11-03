//go:build pkcs11

package keymanager

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"

	"github.com/razatechofficial/mail-os/config"
)

// pkcs11Sessions is the size of the session pool. A session runs one
// operation at a time; wrapping is short, and data keys are unwrapped once
// per replica, so a few cover a replica.
const pkcs11Sessions = 4

// gcmNonceSize and gcmTagBits are the AES-GCM parameters of wrapped keys.
const (
	gcmNonceSize = 12
	gcmTagBits   = 128
)

// PKCS11Device is an HSM reached through its PKCS#11 module. Key-encryption
// keys are AES-256 token objects, sensitive and never extractable, named by
// label; data keys are wrapped with CKM_AES_GCM under them. Sessions are
// pooled and logged in with the user PIN. When the token is lost (removed,
// sessions closed, logged out, library finalized) the device
// re-initializes, re-opens its sessions, logs in again and retries the
// operation once.
type PKCS11Device struct {
	module, tokenLabel, pin string
	ctx                     *pkcs11.Ctx

	// mu guards the connection: read-locked to take the pool, write-locked
	// while reconnecting.
	mu       sync.RWMutex
	slot     uint
	gen      uint64
	sessions chan pkcs11.SessionHandle

	reconnectMu sync.Mutex

	handlesMu sync.Mutex
	handles   map[string]pkcs11.ObjectHandle
}

var _ Device = (*PKCS11Device)(nil)

// openPKCS11Device loads the module, finds the token by label and logs in.
func openPKCS11Device(cfg config.KeyManagerPKCS11) (*PKCS11Device, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	pin, err := cfg.ResolvePIN()
	if err != nil {
		return nil, err
	}
	p := pkcs11.New(cfg.ModulePath)
	if p == nil {
		return nil, fmt.Errorf("pkcs11: cannot load module %s", cfg.ModulePath)
	}
	d := &PKCS11Device{module: cfg.ModulePath, tokenLabel: cfg.TokenLabel, pin: pin, ctx: p,
		handles: map[string]pkcs11.ObjectHandle{}}
	if err := d.connect(); err != nil {
		p.Destroy()
		return nil, err
	}
	return d, nil
}

// Close logs out, closes the sessions and unloads the module.
func (d *PKCS11Device) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	_ = d.ctx.CloseAllSessions(d.slot)
	_ = d.ctx.Finalize()
	d.ctx.Destroy()
}

// connect initializes the library, opens the pool and logs in. The caller
// holds mu for writing, or owns d exclusively.
func (d *PKCS11Device) connect() error {
	if err := d.ctx.Initialize(); err != nil && !isCKR(err, pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		return fmt.Errorf("pkcs11: initialize %s: %w", d.module, err)
	}
	slot, err := d.findSlot()
	if err != nil {
		_ = d.ctx.Finalize()
		return err
	}
	pool := make(chan pkcs11.SessionHandle, pkcs11Sessions)
	for i := 0; i < pkcs11Sessions; i++ {
		sh, err := d.ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			_ = d.ctx.CloseAllSessions(slot)
			_ = d.ctx.Finalize()
			return fmt.Errorf("pkcs11: open session: %w", err)
		}
		if i == 0 {
			// Login state belongs to the application, not the session:
			// one login serves every session of the pool.
			if err := d.ctx.Login(sh, pkcs11.CKU_USER, d.pin); err != nil && !isCKR(err, pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
				_ = d.ctx.CloseAllSessions(slot)
				_ = d.ctx.Finalize()
				return fmt.Errorf("pkcs11: log in to token %q: %w", d.tokenLabel, err)
			}
		}
		pool <- sh
	}
	d.slot, d.sessions = slot, pool
	d.gen++
	d.handlesMu.Lock()
	d.handles = map[string]pkcs11.ObjectHandle{}
	d.handlesMu.Unlock()
	return nil
}

func (d *PKCS11Device) findSlot() (uint, error) {
	slots, err := d.ctx.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("pkcs11: list slots: %w", err)
	}
	for _, s := range slots {
		info, err := d.ctx.GetTokenInfo(s)
		if err == nil && strings.TrimRight(info.Label, " \x00") == d.tokenLabel {
			return s, nil
		}
	}
	return 0, fmt.Errorf("pkcs11: no token labelled %q", d.tokenLabel)
}

// reconnect starts over after the token was lost, unless another caller
// already did since generation seen.
func (d *PKCS11Device) reconnect(seen uint64) error {
	d.reconnectMu.Lock()
	defer d.reconnectMu.Unlock()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.gen != seen {
		return nil
	}
	_ = d.ctx.Finalize()
	return d.connect()
}

// lostToken reports errors after which the sessions or the login are gone,
// or a cached object handle no longer names the object.
func lostToken(err error) bool {
	var e pkcs11.Error
	if !errors.As(err, &e) {
		return false
	}
	switch uint(e) {
	case pkcs11.CKR_SESSION_HANDLE_INVALID, pkcs11.CKR_SESSION_CLOSED, pkcs11.CKR_DEVICE_REMOVED,
		pkcs11.CKR_TOKEN_NOT_PRESENT, pkcs11.CKR_USER_NOT_LOGGED_IN, pkcs11.CKR_DEVICE_ERROR,
		pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED, pkcs11.CKR_KEY_HANDLE_INVALID, pkcs11.CKR_OBJECT_HANDLE_INVALID:
		return true
	}
	return false
}

func isCKR(err error, code uint) bool {
	var e pkcs11.Error
	return errors.As(err, &e) && uint(e) == code
}

// do runs fn on a pooled session; when the token was lost it reconnects
// and runs fn once more.
func (d *PKCS11Device) do(ctx context.Context, fn func(sh pkcs11.SessionHandle) error) error {
	gen, err := d.try(ctx, fn)
	if err == nil || !lostToken(err) {
		return err
	}
	if rerr := d.reconnect(gen); rerr != nil {
		return fmt.Errorf("%w; reconnect failed: %v", err, rerr)
	}
	_, err = d.try(ctx, fn)
	return err
}

func (d *PKCS11Device) try(ctx context.Context, fn func(sh pkcs11.SessionHandle) error) (uint64, error) {
	d.mu.RLock()
	pool, gen := d.sessions, d.gen
	d.mu.RUnlock()
	var sh pkcs11.SessionHandle
	select {
	case sh = <-pool:
	case <-ctx.Done():
		return gen, fmt.Errorf("pkcs11: no free session: %w", ctx.Err())
	}
	defer func() { pool <- sh }()
	return gen, fn(sh)
}

// find returns the objects matching template (at most two: enough to tell
// a unique label from a duplicated one).
func (d *PKCS11Device) find(sh pkcs11.SessionHandle, template []*pkcs11.Attribute) ([]pkcs11.ObjectHandle, error) {
	if err := d.ctx.FindObjectsInit(sh, template); err != nil {
		return nil, err
	}
	defer func() { _ = d.ctx.FindObjectsFinal(sh) }()
	objs, _, err := d.ctx.FindObjects(sh, 2)
	return objs, err
}

func secretKeyTemplate(label string) []*pkcs11.Attribute {
	return []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
}

// key finds exactly one secret key by label, caching its handle.
func (d *PKCS11Device) key(sh pkcs11.SessionHandle, label string) (pkcs11.ObjectHandle, error) {
	d.handlesMu.Lock()
	h, ok := d.handles[label]
	d.handlesMu.Unlock()
	if ok {
		return h, nil
	}
	objs, err := d.find(sh, secretKeyTemplate(label))
	if err != nil {
		return 0, err
	}
	switch len(objs) {
	case 0:
		return 0, fmt.Errorf("pkcs11: no key labelled %q", label)
	case 1:
	default:
		return 0, fmt.Errorf("pkcs11: several keys labelled %q; labels must be unique", label)
	}
	d.handlesMu.Lock()
	d.handles[label] = objs[0]
	d.handlesMu.Unlock()
	return objs[0], nil
}

// forget drops a cached handle the token no longer knows.
func (d *PKCS11Device) forget(label string, err error) {
	if isCKR(err, pkcs11.CKR_KEY_HANDLE_INVALID) || isCKR(err, pkcs11.CKR_OBJECT_HANDLE_INVALID) {
		d.handlesMu.Lock()
		delete(d.handles, label)
		d.handlesMu.Unlock()
	}
}

// EnsureKEK creates the AES-256 key-encryption key when the token has none.
// Provision it in the key ceremony when several replicas start at once:
// two replicas creating it together leave two keys under one label, which
// is refused rather than used.
func (d *PKCS11Device) EnsureKEK(ctx context.Context, label string) error {
	return d.do(ctx, func(sh pkcs11.SessionHandle) error {
		objs, err := d.find(sh, secretKeyTemplate(label))
		if err != nil {
			return err
		}
		if len(objs) > 1 {
			return fmt.Errorf("pkcs11: several keys labelled %q; keep one key-encryption key per label", label)
		}
		if len(objs) == 1 {
			return nil
		}
		_, err = d.ctx.GenerateKey(sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}, append(secretKeyTemplate(label),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		))
		if err != nil {
			return fmt.Errorf("pkcs11: create key-encryption key %q: %w", label, err)
		}
		return nil
	})
}

// Encrypt wraps plain under the key labelled label: nonce ||
// AES-256-GCM(plain, aad).
func (d *PKCS11Device) Encrypt(ctx context.Context, label string, plain, aad []byte) ([]byte, error) {
	nonce := make([]byte, gcmNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	var out []byte
	err := d.do(ctx, func(sh pkcs11.SessionHandle) error {
		h, err := d.key(sh, label)
		if err != nil {
			return err
		}
		params := pkcs11.NewGCMParams(nonce, aad, gcmTagBits)
		defer params.Free()
		if err := d.ctx.EncryptInit(sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}, h); err != nil {
			d.forget(label, err)
			return err
		}
		ct, err := d.ctx.Encrypt(sh, plain)
		if err != nil {
			return err
		}
		out = append(append([]byte(nil), nonce...), ct...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("pkcs11: wrap under %q: %w", label, err)
	}
	return out, nil
}

// Decrypt unwraps a value Encrypt sealed under label with the same aad.
func (d *PKCS11Device) Decrypt(ctx context.Context, label string, sealed, aad []byte) ([]byte, error) {
	if len(sealed) < gcmNonceSize+gcmTagBits/8 {
		return nil, errors.New("pkcs11: wrapped value too short")
	}
	var plain []byte
	err := d.do(ctx, func(sh pkcs11.SessionHandle) error {
		h, err := d.key(sh, label)
		if err != nil {
			return err
		}
		params := pkcs11.NewGCMParams(sealed[:gcmNonceSize], aad, gcmTagBits)
		defer params.Free()
		if err := d.ctx.DecryptInit(sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}, h); err != nil {
			d.forget(label, err)
			return err
		}
		plain, err = d.ctx.Decrypt(sh, sealed[gcmNonceSize:])
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("pkcs11: unwrap under %q: %w", label, err)
	}
	return plain, nil
}
