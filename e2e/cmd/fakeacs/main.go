//go:build e2e

// Command fakeacs is the ACS the e2e suite runs MailOS against: it serves
// internal/testutil/fakeacs (the acs.v1 calls MailOS makes, the platform
// scope, user subjects only, the 8 h expiry horizon, expired relationships
// granting nothing) over plaintext gRPC on loopback. Each call must carry a
// bearer token the IAM issued for api://acs (verified against the issuer's
// JWKS), as ACS's app gateway requires; the client certificate binding is
// not modelled. Relationships live in memory for the life of the process.
//
//	fakeacs -addr 127.0.0.1:18184 -iam-issuer http://127.0.0.1:18190
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"google.golang.org/grpc"

	"github.com/razatechofficial/mail-os/infrastructure/jwt"
	"github.com/razatechofficial/mail-os/internal/testutil/fakeacs"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18184", "gRPC listen address (loopback)")
	issuer := flag.String("iam-issuer", "", "the IAM whose api://acs tokens are accepted")
	flag.Parse()
	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatalf("fakeacs: -addr: %v", err)
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		log.Fatalf("fakeacs: refusing to listen on %s: it is plaintext", *addr)
	}
	if *issuer == "" {
		log.Fatal("fakeacs: -iam-issuer is required")
	}
	v := jwt.NewVerifier(jwt.Config{Issuer: *issuer, MinRefresh: time.Second})
	a := fakeacs.New()
	a.Authenticate = func(ctx context.Context, token string) error {
		if token == "" {
			return errors.New("no bearer token")
		}
		claims, err := v.Verify(ctx, token, "at+jwt")
		if err != nil {
			return err
		}
		if err := v.CheckTimes(claims); err != nil {
			return err
		}
		if !slices.Contains(jwt.Audiences(claims), "api://acs") {
			return fmt.Errorf("audience %v is not api://acs", jwt.Audiences(claims))
		}
		return nil
	}
	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("fakeacs: %v", err)
	}
	s := grpc.NewServer()
	a.Register(s)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		s.GracefulStop()
	}()
	log.Printf("fakeacs: listening on %s, tokens from %s", *addr, *issuer)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("fakeacs: %v", err)
	}
}
