package keymanager

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/razatechofficial/mail-os/config"
)

// KMSAPI is the part of the AWS KMS client AWSKMS calls.
type KMSAPI interface {
	DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, opts ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	Encrypt(ctx context.Context, in *kms.EncryptInput, opts ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(ctx context.Context, in *kms.DecryptInput, opts ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// AWSKMS is AWS KMS as a RemoteKEKService. A data key is encrypted under a
// symmetric KMS key with the encryption context {"mailos": aad}, so KMS
// refuses to decrypt it for another kid; the context is also logged by
// CloudTrail.
type AWSKMS struct {
	api KMSAPI
}

var _ RemoteKEKService = (*AWSKMS)(nil)

// kmsOpenTimeout bounds connecting and resolving the key-encryption keys.
const kmsOpenTimeout = 15 * time.Second

// OpenAWSKMS connects with the default credential chain (IRSA, task or
// instance role; never static keys in configuration).
func OpenAWSKMS(ctx context.Context, cfg config.KeyManagerKMS) (*AWSKMS, error) {
	var opts []func(*awsconfig.LoadOptions) error
	if cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.Region))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("kms: aws config: %w", err)
	}
	if awsCfg.Region == "" {
		return nil, errors.New("kms: no AWS region; set KEY_MANAGER_KMS_REGION or AWS_REGION")
	}
	client := kms.NewFromConfig(awsCfg, func(o *kms.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
	})
	return NewAWSKMS(client), nil
}

// NewAWSKMS returns the service over a KMS client.
func NewAWSKMS(api KMSAPI) *AWSKMS { return &AWSKMS{api: api} }

// kmsEncryptionContext binds a wrapped data key to its kid.
func kmsEncryptionContext(aad []byte) map[string]string {
	return map[string]string{"mailos": string(aad)}
}

// Resolve checks the key is an enabled symmetric encryption key and returns
// its ARN, so a repointed alias cannot swap the key under stored data keys.
func (a *AWSKMS) Resolve(ctx context.Context, keyID string) (string, error) {
	out, err := a.api.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return "", fmt.Errorf("kms: key-encryption key %q: %w", keyID, err)
	}
	md := out.KeyMetadata
	switch {
	case md == nil || md.Arn == nil:
		return "", fmt.Errorf("kms: key-encryption key %q has no metadata", keyID)
	case md.KeyState != kmstypes.KeyStateEnabled:
		return "", fmt.Errorf("kms: key-encryption key %q is %s", keyID, md.KeyState)
	case md.KeyUsage != kmstypes.KeyUsageTypeEncryptDecrypt || md.KeySpec != kmstypes.KeySpecSymmetricDefault:
		return "", fmt.Errorf("kms: key-encryption key %q is not a symmetric encryption key", keyID)
	}
	return aws.ToString(md.Arn), nil
}

// Encrypt encrypts a data key under the KMS key.
func (a *AWSKMS) Encrypt(ctx context.Context, keyID string, plain, aad []byte) ([]byte, error) {
	out, err := a.api.Encrypt(ctx, &kms.EncryptInput{
		KeyId: aws.String(keyID), Plaintext: plain, EncryptionContext: kmsEncryptionContext(aad),
		EncryptionAlgorithm: kmstypes.EncryptionAlgorithmSpecSymmetricDefault,
	})
	if err != nil {
		return nil, err
	}
	return out.CiphertextBlob, nil
}

// Decrypt decrypts a data key, naming the KMS key so a blob of another key
// is refused rather than decrypted with it.
func (a *AWSKMS) Decrypt(ctx context.Context, keyID string, ciphertext, aad []byte) ([]byte, error) {
	out, err := a.api.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob: ciphertext, KeyId: aws.String(keyID), EncryptionContext: kmsEncryptionContext(aad),
		EncryptionAlgorithm: kmstypes.EncryptionAlgorithmSpecSymmetricDefault,
	})
	if err != nil {
		return nil, err
	}
	return out.Plaintext, nil
}
