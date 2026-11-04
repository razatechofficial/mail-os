package mailer

import (
	"github.com/razatechofficial/mail-os/domain/message"
)

// classifyPermanent decides the reason of a 5xx reply at MAIL, RCPT or
// DATA with the rule provider delivery events share
// (message.ClassifyRefusal): only a reply naming the recipient bounces; a
// refused sender, session or sending-domain policy is configuration.
func classifyPermanent(stage string, code int, msg string) message.Reason {
	return message.ClassifyRefusal(message.RefusalStage(stage), code, msg)
}
