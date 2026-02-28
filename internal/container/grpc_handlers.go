package container

import (
	grpchandler "github.com/razatechofficial/mail-os/internal/adapter/inbound/grpc/handler"
)

type GRPCHandlers struct {
	MailService *grpchandler.MailService
}

func (c *Container) buildGRPCHandlers() *GRPCHandlers {
	return &GRPCHandlers{
		MailService: grpchandler.NewMailService(c.Services.Message),
	}
}
