// Command redact-auth-mail redacts the authentication mail a deployment
// stored before persistence masking (ADR 0001 §3.6, plan 0.20): in every
// message of an authentication-class topic whose body is still stored,
// the one-time codes and token-bearing links in its template data become
// redaction descriptors, and every occurrence of them in its subject,
// bodies and last error is replaced. Run it once after the migrations of
// the release that introduced persistence masking; running it again
// changes nothing. It uses the server's database configuration, prints
// only counts, and exits 1 on any error.
package main

import (
	"context"
	"os"
	"time"

	appmessage "github.com/razatechofficial/mail-os/application/message"
	"github.com/razatechofficial/mail-os/config"
	"github.com/razatechofficial/mail-os/infrastructure/persistence/postgres"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

// Version and Commit are set by the build (-ldflags -X).
var (
	Version = "dev"
	Commit  = ""
)

func main() {
	_ = logger.InitSimple("info", "json")
	cfg, err := config.LoadDatabase()
	if err != nil {
		logger.Fatal("config", logger.Err(err))
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	db, err := postgres.NewConnection(ctx, cfg)
	if err != nil {
		logger.Fatal("database", logger.Err(err))
	}
	defer db.Close()
	rep, err := appmessage.RedactStored(ctx, postgres.NewMessageRepository(db), 500)
	if err != nil {
		logger.Error("redacting stored authentication mail", logger.Int("scanned", rep.Scanned), logger.Int("redacted", rep.Redacted), logger.Err(err))
		os.Exit(1)
	}
	logger.Info("stored authentication mail redacted", logger.String("version", Version),
		logger.Int("scanned", rep.Scanned), logger.Int("redacted", rep.Redacted))
}
