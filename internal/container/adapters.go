package container

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/razatechofficial/mail-os/internal/adapter/outbound/crypto"
	"github.com/razatechofficial/mail-os/internal/adapter/outbound/eventbus"
	"github.com/razatechofficial/mail-os/internal/adapter/outbound/mailer"
	smtpmail "github.com/razatechofficial/mail-os/internal/adapter/outbound/mailer/smtp"
	"github.com/razatechofficial/mail-os/internal/adapter/outbound/postgres"
	"github.com/razatechofficial/mail-os/internal/adapter/outbound/rediscache"
	"github.com/razatechofficial/mail-os/internal/adapter/outbound/renderer"
	"github.com/razatechofficial/mail-os/internal/port"
	"github.com/razatechofficial/mail-os/pkg/logger"
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

	if c.cfg.SMTP.Enabled {
		smtpSender := smtpmail.New(smtpmail.Config{
			Host:     c.cfg.SMTP.Host,
			Port:     c.cfg.SMTP.Port,
			Username: c.cfg.SMTP.Username,
			Password: c.cfg.SMTP.Password,
			FromAddr: c.cfg.SMTP.FromAddr,
		})
		mailRouter.AddProvider(smtpSender, 100, 100, 5, 30*time.Second)
		logger.Info("smtp provider registered", logger.String("host", c.cfg.SMTP.Host))
	}

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
