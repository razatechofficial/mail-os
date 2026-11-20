// Command verify-sent is the evidence custodian's check of a message (ADR
// 0001 §3.14 class (a)): given a copy of its subject, text and HTML,
// rebuilt from the message's template version and stored variables (with
// the secret the IAM recorded, when a case needs it), it reports whether
// each part matches the HMAC-SHA-256 kept when the message was sent. The
// hashes are keyed by the key manager's evidence key, so only a deployment
// that holds the key can check them; this command uses the server's
// configuration and key manager. It prints the result as JSON and exits 0
// when every part matches, 1 when one does not, 2 on a usage or system
// error. It reads only the files it is given and never prints content.
//
//	mailos-verify-sent -tenant <uuid> -message <id> -subject-file s.txt -text-file t.txt -html-file h.html
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/razatechofficial/mail-os/config"
	"github.com/razatechofficial/mail-os/internal/container"
	"github.com/razatechofficial/mail-os/pkg/logger"
)

// Version and Commit are set by the build (-ldflags -X).
var (
	Version = "dev"
	Commit  = ""
)

func read(name string) string {
	if name == "" {
		return ""
	}
	raw, err := os.ReadFile(name)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify-sent:", err)
		os.Exit(2)
	}
	return string(raw)
}

func main() {
	tenant := flag.String("tenant", "", "the message's tenant (IAM tenant UUID)")
	message := flag.String("message", "", "the message id")
	subjectFile := flag.String("subject-file", "", "file holding the subject, exactly (a final newline is dropped)")
	textFile := flag.String("text-file", "", "file holding the text part, exactly")
	htmlFile := flag.String("html-file", "", "file holding the HTML part, exactly")
	flag.Parse()
	if *tenant == "" || *message == "" {
		fmt.Fprintln(os.Stderr, "usage: mailos-verify-sent -tenant <uuid> -message <id> [-subject-file f] [-text-file f] [-html-file f]")
		os.Exit(2)
	}
	_ = logger.InitSimple("error", "json")
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify-sent: config:", err)
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	c, err := container.New(ctx, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify-sent:", err)
		os.Exit(2)
	}
	defer c.Close()
	subject := strings.TrimSuffix(read(*subjectFile), "\n")
	check, err := c.Messages.VerifySent(ctx, *tenant, *message, subject, read(*textFile), read(*htmlFile))
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify-sent:", err)
		os.Exit(2)
	}
	out, _ := json.Marshal(map[string]any{"message_id": *message, "kid": check.KeyID, "subject": check.Subject,
		"text": check.Text, "html": check.HTML, "match": check.Match(), "version": Version})
	fmt.Println(string(out))
	if !check.Match() {
		os.Exit(1)
	}
}
