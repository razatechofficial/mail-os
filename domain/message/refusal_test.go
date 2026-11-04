package message

import "testing"

// Hard-bounce diagnostics as providers' delivery webhooks carry them: a
// refusal of the sender or its policy never suppresses the recipient.
func TestRefusesSender_ProviderDiagnostics(t *testing.T) {
	for _, c := range []struct {
		diagnostic string
		sender     bool
	}{
		{"550 5.1.1 unknown", false},
		{"Permanent General: smtp; 550 5.1.1 user unknown", false},
		{"HardBounce: The server was unable to deliver your message (ex: unknown user, mailbox not found).", false},
		{"10 550 5.1.1 The email account that you tried to reach does not exist.", false},
		{"Permanent OnAccountSuppressionList: Amazon SES did not send the message to this address", false},
		{"bounce 550 5.7.26 Unauthenticated email from bank.example is not accepted due to domain's DMARC policy.", true},
		{"550 5.7.1 Relaying denied", true},
		{"5.7.60 SMTP; Client does not have permissions to send as this sender", true},
		{"Permanent General: smtp; 554 5.7.1 Service unavailable; Client host [203.0.113.5] blocked using zen.spamhaus.org", true},
		{"550 5.7.501 Access denied, spam abuse detected. The sending account has been banned.", true},
		{"535 Authentication failed", true},
		{"Sender address rejected: Domain not found", true},
	} {
		if got := RefusesSender(c.diagnostic); got != c.sender {
			t.Errorf("RefusesSender(%q) = %v, want %v", c.diagnostic, got, c.sender)
		}
	}
}
