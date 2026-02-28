package container

import (
	"encoding/hex"
	"fmt"

	"github.com/razatechofficial/mail-os/internal/adapter/outbound/crypto"
	"github.com/razatechofficial/mail-os/internal/adapter/outbound/eventbus"
	"github.com/razatechofficial/mail-os/internal/adapter/outbound/mailer"
	"github.com/razatechofficial/mail-os/internal/adapter/outbound/postgres"
	"github.com/razatechofficial/mail-os/internal/adapter/outbound/rediscache"
	"github.com/razatechofficial/mail-os/internal/adapter/outbound/renderer"
	"github.com/razatechofficial/mail-os/internal/port"
)

type Adapters struct {
	Cache      port.Cache
	Hasher     port.Hasher
	Encryptor  port.Encryptor
	Signer     port.Signer
	Renderer   port.TemplateRenderer
	TxManager  port.TxManager
	EventBus   *eventbus.Bus
	MailRouter *mailer.Router
}

func (c *Container) buildAdapters() *Adapters {
	cache := rediscache.NewCache(c.Redis)

	hasher := crypto.NewHasher()

	encKey, err := hex.DecodeString(c.cfg.Encryption.Key)
	if err != nil {
		panic(fmt.Sprintf("container: invalid encryption key hex: %v", err))
	}
	encryptor, err := crypto.NewEncryptor(encKey)
	if err != nil {
		panic(fmt.Sprintf("container: failed to create encryptor: %v", err))
	}

	signer := crypto.NewSigner([]byte(c.cfg.Encryption.HMACSecret))

	tmplRenderer := renderer.New()

	txManager := postgres.NewTxManager(c.DB.Pool)

	bus := eventbus.New()

	mailRouter := mailer.NewRouter()

	return &Adapters{
		Cache:      cache,
		Hasher:     hasher,
		Encryptor:  encryptor,
		Signer:     signer,
		Renderer:   tmplRenderer,
		TxManager:  txManager,
		EventBus:   bus,
		MailRouter: mailRouter,
	}
}
