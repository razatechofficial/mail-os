package keymanager

import (
	"context"
	"fmt"

	app "github.com/razatechofficial/mail-os/application/keymanager"
	"github.com/razatechofficial/mail-os/config"
	domain "github.com/razatechofficial/mail-os/domain/keymanager"
)

// Opener builds KEKs; its fields are the HSM and KMS connections, opened
// once and shared by the current and the new KEK. Tests replace them.
type Opener struct {
	OpenDevice func(config.KeyManagerPKCS11) (Device, error)
	OpenKMS    func(context.Context, config.KeyManagerKMS) (RemoteKEKService, error)
	// OpenRemote opens the GCP, Azure and Vault key services.
	OpenRemote func(ctx context.Context, provider string, cfg config.KeyManager) (RemoteKEKService, error)

	dev    Device
	kms    RemoteKEKService
	remote map[string]RemoteKEKService
}

// OpenRemoteKEKService opens a GCP, Azure or Vault key service.
func OpenRemoteKEKService(ctx context.Context, provider string, cfg config.KeyManager) (RemoteKEKService, error) {
	switch provider {
	case config.KeyProviderGCPKMS:
		return OpenGCPKMS(ctx, cfg.GCPKMS)
	case config.KeyProviderAzureKeyVault:
		return OpenAzureKeyVault(ctx, cfg.Azure)
	case config.KeyProviderVaultTransit:
		return OpenVaultTransit(ctx, cfg.Vault)
	}
	return nil, fmt.Errorf("no key service %q", provider)
}

// Open builds the KEKs configuration names: KEY_MANAGER_PROVIDER's and,
// when one of the KEY_MANAGER_*NEW* settings is set, the new one. An HSM
// or KMS that cannot be reached stops the server; there is no fallback to
// the software KEK. close releases the HSM session.
func Open(ctx context.Context, cfg config.KeyManager) (keks *app.KEKs, close func(), err error) {
	o := &Opener{
		OpenDevice: OpenPKCS11,
		OpenKMS: func(ctx context.Context, c config.KeyManagerKMS) (RemoteKEKService, error) {
			return OpenAWSKMS(ctx, c)
		},
		OpenRemote: OpenRemoteKEKService,
	}
	return o.Open(ctx, cfg)
}

// Open is Open with the opener's connections.
func (o *Opener) Open(ctx context.Context, cfg config.KeyManager) (*app.KEKs, func(), error) {
	ctx, cancel := context.WithTimeout(ctx, kmsOpenTimeout)
	defer cancel()
	release := func() {
		if o.dev != nil {
			o.dev.Close()
		}
	}
	current, err := o.kek(ctx, cfg, cfg.Provider, false)
	if err != nil {
		release()
		return nil, nil, err
	}
	var next app.KEK
	if p := cfg.NewKEKProvider(); p != "" {
		if next, err = o.kek(ctx, cfg, p, true); err != nil {
			release()
			return nil, nil, fmt.Errorf("new key-encryption key: %w", err)
		}
	}
	keks, err := app.NewKEKs(current, next)
	if err != nil {
		release()
		return nil, nil, err
	}
	return keks, release, nil
}

func (o *Opener) kek(ctx context.Context, cfg config.KeyManager, provider string, isNew bool) (app.KEK, error) {
	switch provider {
	case config.KeyProviderSoftware:
		if isNew {
			return NewSoftwareKEK("KEY_MANAGER_NEW_MASTER_KEY", cfg.NewMasterKey)
		}
		return NewSoftwareKEK("KEY_MANAGER_MASTER_KEY", cfg.MasterKey)
	case config.KeyProviderPKCS11:
		if o.dev == nil {
			dev, err := o.OpenDevice(cfg.PKCS11)
			if err != nil {
				return nil, err
			}
			o.dev = dev
		}
		label := cfg.PKCS11.KEKLabel
		if isNew {
			label = cfg.PKCS11.NewKEKLabel
		}
		return NewDeviceKEK(ctx, o.dev, label)
	case config.KeyProviderKMS:
		if o.kms == nil {
			svc, err := o.OpenKMS(ctx, cfg.KMS)
			if err != nil {
				return nil, err
			}
			o.kms = svc
		}
		key := cfg.KMS.KEKKeyID
		if isNew {
			key = cfg.KMS.NewKEKKeyID
		}
		return NewExternalKEK(ctx, domain.ProviderKMS, o.kms, key)
	case config.KeyProviderGCPKMS, config.KeyProviderAzureKeyVault, config.KeyProviderVaultTransit:
		svc := o.remote[provider]
		if svc == nil {
			var err error
			if svc, err = o.OpenRemote(ctx, provider, cfg); err != nil {
				return nil, err
			}
			if o.remote == nil {
				o.remote = map[string]RemoteKEKService{}
			}
			o.remote[provider] = svc
		}
		// The config and domain provider names are the same strings.
		return NewExternalKEK(ctx, provider, svc, cfg.KEKKey(provider, isNew))
	}
	return nil, fmt.Errorf("KEY_MANAGER_PROVIDER must be software, pkcs11, kms, gcp_kms, azure_key_vault or vault_transit, not %q", provider)
}
