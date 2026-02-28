package apikey

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/razatechofficial/mail-os/internal/domain"
	"github.com/razatechofficial/mail-os/internal/port"
	"github.com/razatechofficial/mail-os/pkg/errors"
	"github.com/razatechofficial/mail-os/pkg/id"
)

type service struct {
	repo   Repository
	hasher port.Hasher
}

func NewService(repo Repository, hasher port.Hasher) Service {
	return &service{repo: repo, hasher: hasher}
}

func (s *service) Create(ctx context.Context, input CreateInput) (*domain.APIKey, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", fmt.Errorf("apikey.Create: %w", err)
	}
	plaintext := "mo_" + hex.EncodeToString(raw)
	prefix := plaintext
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	hash, err := s.hasher.Hash(plaintext)
	if err != nil {
		return nil, "", fmt.Errorf("apikey.Create: %w", err)
	}
	key := &domain.APIKey{
		ID:         domain.APIKeyID(id.New()),
		OrgID:      domain.OrganizationID(input.OrgID),
		Name:       input.Name,
		KeyHash:    hash,
		Prefix:     prefix,
		Scopes:     input.Scopes,
		ExpiresAt:  input.ExpiresAt,
		IsActive:   true,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	if err := s.repo.Create(ctx, key); err != nil {
		return nil, "", fmt.Errorf("apikey.Create: %w", err)
	}
	return key, plaintext, nil
}

func (s *service) GetByID(ctx context.Context, orgID domain.OrganizationID, id domain.APIKeyID) (*domain.APIKey, error) {
	key, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("apikey.GetByID: %w", err)
	}
	if key.OrgID != orgID {
		return nil, fmt.Errorf("apikey.GetByID: %w", errors.ErrNotFound)
	}
	return key, nil
}

func (s *service) ValidateKey(ctx context.Context, plaintext string) (*domain.APIKey, error) {
	if len(plaintext) < 8 {
		return nil, fmt.Errorf("apikey.ValidateKey: invalid key format")
	}
	prefix := plaintext[:8]
	keys, err := s.repo.FindByPrefix(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("apikey.ValidateKey: %w", err)
	}
	for _, k := range keys {
		if !k.IsActive || (k.ExpiresAt != nil && k.ExpiresAt.Before(time.Now())) {
			continue
		}
		if err := s.hasher.Compare(k.KeyHash, plaintext); err == nil {
			return k, nil
		}
	}
	return nil, fmt.Errorf("apikey.ValidateKey: invalid key")
}

func (s *service) Revoke(ctx context.Context, orgID domain.OrganizationID, id domain.APIKeyID) error {
	key, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("apikey.Revoke: %w", err)
	}
	if key.OrgID != orgID {
		return fmt.Errorf("apikey.Revoke: unauthorized")
	}
	if err := s.repo.SoftDelete(ctx, id); err != nil {
		return fmt.Errorf("apikey.Revoke: %w", err)
	}
	return nil
}

func (s *service) List(ctx context.Context, orgID domain.OrganizationID, params ListParams) ([]*domain.APIKey, int, error) {
	keys, total, err := s.repo.FindAll(ctx, orgID, params)
	if err != nil {
		return nil, 0, fmt.Errorf("apikey.List: %w", err)
	}
	return keys, total, nil
}
