package suppression

import (
	"testing"

	"github.com/razatechofficial/mail-os/domain/message"
)

func TestBlocks(t *testing.T) {
	if TypeUnsubscribe.Blocks(message.TypeTransactional) || !TypeUnsubscribe.Blocks(message.TypeMarketing) {
		t.Fatal("unsubscribe must stop marketing only")
	}
	if !TypeBounce.Blocks(message.TypeTransactional) || !TypeManual.Blocks(message.TypeNotification) {
		t.Fatal("bounce and manual stop everything")
	}
}

func TestValidate(t *testing.T) {
	if (Suppression{Email: NormalizeEmail(" A@Example.com "), Type: TypeManual}).Validate() != nil {
		t.Fatal("valid suppression refused")
	}
	if (Suppression{Email: "nope", Type: "hard"}).Validate() == nil {
		t.Fatal("invalid suppression accepted")
	}
}
