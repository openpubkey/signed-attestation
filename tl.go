package signedattestation

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	rclient "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	DefaultRekorURL = "https://rekor.sigstore.dev"
	DefaultCtxKey   = "tl"
)

type tlCtxKey string

type TL interface {
	UploadLogEntry(ctx context.Context, pkToken *pktoken.PKToken, payload, signature []byte, signer crypto.Signer) ([]byte, error)
	VerifyLogEntry(ctx context.Context, entryBytes []byte) error
}

type MockTL struct {
	UploadLogEntryFunc func(ctx context.Context, pkToken *pktoken.PKToken, payload, signature []byte, signer crypto.Signer) ([]byte, error)
	VerifyLogEntryFunc func(ctx context.Context, entryBytes []byte) error
}

func (tl *MockTL) UploadLogEntry(ctx context.Context, pkToken *pktoken.PKToken, payload, signature []byte, signer crypto.Signer) ([]byte, error) {
	if tl.UploadLogEntryFunc != nil {
		return tl.UploadLogEntryFunc(ctx, pkToken, payload, signature, signer)
	}
	return nil, nil
}

func (tl *MockTL) VerifyLogEntry(ctx context.Context, entryBytes []byte) error {
	if tl.VerifyLogEntryFunc != nil {
		return tl.VerifyLogEntryFunc(ctx, entryBytes)
	}
	return nil
}

type RekorTL struct{}

// UploadLogEntry submits a PK token signature to the transparency log
func (tl *RekorTL) UploadLogEntry(ctx context.Context, pkToken *pktoken.PKToken, payload, signature []byte, signer crypto.Signer) ([]byte, error) {
	// generate self-signed x509 cert to wrap PK token
	pubCert, err := CreateX509Cert(pkToken, signer)
	if err != nil {
		return nil, fmt.Errorf("Error creating x509 cert: %w", err)
	}

	// generate hash of payload
	hasher := sha256.New()
	hasher.Write(payload)

	// upload entry
	rekorClient, err := rclient.GetRekorClient(DefaultRekorURL)
	if err != nil {
		return nil, fmt.Errorf("Error creating rekor client: %w", err)
	}
	entry, err := cosign.TLogUpload(ctx, rekorClient, signature, hasher, pubCert)
	if err != nil {
		return nil, fmt.Errorf("Error uploading tlog: %w", err)
	}
	entryBytes, err := entry.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("error marshalling TL entry: %w", err)
	}
	return entryBytes, nil
}

// VerifyLogEntry verifies a transparency log entry
func (tl *RekorTL) VerifyLogEntry(ctx context.Context, entryBytes []byte) error {
	entry := new(models.LogEntryAnon)
	err := entry.UnmarshalBinary(entryBytes)
	if err != nil {
		return fmt.Errorf("error failed to unmarshal TL entry: %w", err)
	}
	err = entry.Verification.Validate(strfmt.Default)
	if err != nil {
		return fmt.Errorf("TL entry failed validation: %w", err)
	}

	verifier, err := loadVerifier()
	if err != nil {
		return fmt.Errorf("error failed to load TL verifier: %w", err)
	}
	err = verify.VerifyLogEntry(ctx, entry, verifier)
	if err != nil {
		return fmt.Errorf("TL entry failed verification: %w", err)
	}
	return nil
}

func loadVerifier() (signature.Verifier, error) {
	rekorClient, err := rclient.GetRekorClient(DefaultRekorURL)
	if err != nil {
		return nil, fmt.Errorf("error creating rekor client: %w", err)
	}
	// fetch key from server
	keyResp, err := rekorClient.Pubkey.GetPublicKey(nil)
	if err != nil {
		return nil, err
	}
	publicKey := keyResp.Payload

	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return nil, errors.New("failed to decode public key of server")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return signature.LoadVerifier(pub, crypto.SHA256)
}

// CreateX509Cert generates a self-signed x509 cert from a PK token
func CreateX509Cert(pkToken *pktoken.PKToken, signer crypto.Signer) ([]byte, error) {
	pkTokenJSON, err := json.Marshal(pkToken)
	if err != nil {
		return nil, fmt.Errorf("error marshalling PK token to JSON: %w", err)
	}

	// get subject identitifer from pk token
	var payload struct {
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(pkToken.Payload, &payload); err != nil {
		return nil, err
	}

	// encode ephemeral public key
	ecPub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("error marshalling public key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber:            big.NewInt(1),
		Subject:                 pkix.Name{CommonName: payload.Subject},
		RawSubjectPublicKeyInfo: ecPub,
		NotBefore:               time.Now(),
		NotAfter:                time.Now().Add(365 * 24 * time.Hour), // valid for 1 year
		KeyUsage:                x509.KeyUsageDigitalSignature,
		ExtKeyUsage:             []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid:   true,
		DNSNames:                []string{payload.Subject},
		IsCA:                    false,
		SubjectKeyId:            pkTokenJSON,
	}

	// create a self-signed X.509 certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("error creating X.509 certificate: %w", err)
	}
	certBlock := &pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	return pem.EncodeToMemory(certBlock), nil
}
