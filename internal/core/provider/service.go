package provider

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/razatechofficial/mail-os/internal/domain"
	"github.com/razatechofficial/mail-os/internal/port"
	"github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/id"
)

var sensitiveConfigKeys = map[string]bool{
	"api_key": true, "api_secret": true, "secret_key": true,
	"secret": true, "password": true,
}

type service struct {
	repo      Repository
	encryptor port.Encryptor
}

func NewService(repo Repository, encryptor port.Encryptor) Service {
	return &service{repo: repo, encryptor: encryptor}
}

func (s *service) encryptConfig(cfg map[string]any) (map[string]any, error) {
	if cfg == nil {
		return nil, nil
	}
	out := make(map[string]any)
	for k, v := range cfg {
		if !sensitiveConfigKeys[k] {
			out[k] = v
			continue
		}
		str, ok := v.(string)
		if !ok {
			out[k] = v
			continue
		}
		enc, err := s.encryptor.Encrypt([]byte(str))
		if err != nil {
			return nil, err
		}
		out[k] = base64.StdEncoding.EncodeToString(enc)
	}
	return out, nil
}

func (s *service) decryptConfig(cfg map[string]any) (map[string]any, error) {
	if cfg == nil {
		return nil, nil
	}
	out := make(map[string]any)
	for k, v := range cfg {
		if !sensitiveConfigKeys[k] {
			out[k] = v
			continue
		}
		str, ok := v.(string)
		if !ok {
			out[k] = v
			continue
		}
		enc, err := base64.StdEncoding.DecodeString(str)
		if err != nil {
			return nil, err
		}
		dec, err := s.encryptor.Decrypt(enc)
		if err != nil {
			return nil, err
		}
		out[k] = string(dec)
	}
	return out, nil
}

func (s *service) Create(ctx context.Context, input CreateInput) (*domain.Provider, error) {
	cfg, err := s.encryptConfig(input.Configuration)
	if err != nil {
		return nil, fmt.Errorf("provider.Create: %w", err)
	}
	p := &domain.Provider{
		ID:            domain.ProviderID(id.New()),
		OrgID:         domain.OrganizationID(input.OrgID),
		Name:          input.Name,
		Type:          input.Type,
		Configuration: cfg,
		Priority:      input.Priority,
		Weight:        input.Weight,
		DailyLimit:    input.DailyLimit,
		IsActive:      true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	if err := s.repo.Create(ctx, p); err != nil {
		return nil, fmt.Errorf("provider.Create: %w", err)
	}
	return p, nil
}

func (s *service) GetByID(ctx context.Context, orgID domain.OrganizationID, id domain.ProviderID) (*domain.Provider, error) {
	p, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("provider.GetByID: %w", err)
	}
	if p.OrgID != orgID {
		return nil, fmt.Errorf("provider.GetByID: %w", errors.ErrNotFound)
	}
	cfg, err := s.decryptConfig(p.Configuration)
	if err != nil {
		return nil, fmt.Errorf("provider.GetByID: %w", err)
	}
	p.Configuration = cfg
	return p, nil
}

func (s *service) Update(ctx context.Context, orgID domain.OrganizationID, id domain.ProviderID, input UpdateInput) (*domain.Provider, error) {
	p, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("provider.Update: %w", err)
	}
	if p.OrgID != orgID {
		return nil, fmt.Errorf("provider.Update: %w", errors.ErrNotFound)
	}
	if input.Name != nil {
		p.Name = *input.Name
	}
	if input.Configuration != nil {
		cfg, err := s.encryptConfig(input.Configuration)
		if err != nil {
			return nil, fmt.Errorf("provider.Update: %w", err)
		}
		p.Configuration = cfg
	}
	if input.Priority != nil {
		p.Priority = *input.Priority
	}
	if input.Weight != nil {
		p.Weight = *input.Weight
	}
	if input.DailyLimit != nil {
		p.DailyLimit = *input.DailyLimit
	}
	if input.IsActive != nil {
		p.IsActive = *input.IsActive
	}
	p.UpdatedAt = time.Now()
	if err := s.repo.Update(ctx, p); err != nil {
		return nil, fmt.Errorf("provider.Update: %w", err)
	}
	return p, nil
}

func (s *service) Delete(ctx context.Context, orgID domain.OrganizationID, id domain.ProviderID) error {
	p, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("provider.Delete: %w", err)
	}
	if p.OrgID != orgID {
		return fmt.Errorf("provider.Delete: %w", errors.ErrNotFound)
	}
	if err := s.repo.SoftDelete(ctx, id); err != nil {
		return fmt.Errorf("provider.Delete: %w", err)
	}
	return nil
}

func (s *service) List(ctx context.Context, orgID domain.OrganizationID, params ListParams) ([]*domain.Provider, int, error) {
	providers, total, err := s.repo.FindAll(ctx, orgID, params)
	if err != nil {
		return nil, 0, fmt.Errorf("provider.List: %w", err)
	}
	for _, p := range providers {
		cfg, err := s.decryptConfig(p.Configuration)
		if err != nil {
			return nil, 0, fmt.Errorf("provider.List: %w", err)
		}
		p.Configuration = cfg
	}
	return providers, total, nil
}

func (s *service) ListActive(ctx context.Context, orgID domain.OrganizationID) ([]*domain.Provider, error) {
	providers, err := s.repo.FindActive(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("provider.ListActive: %w", err)
	}
	for _, p := range providers {
		cfg, err := s.decryptConfig(p.Configuration)
		if err != nil {
			return nil, fmt.Errorf("provider.ListActive: %w", err)
		}
		p.Configuration = cfg
	}
	return providers, nil
}
