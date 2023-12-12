package signedattestation

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/sigstore/cosign/v2/pkg/cosign"
	rclient "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/models"
)

const (
	RekorURL = "https://rekor.sigstore.dev"
)

func uploadTL(ctx context.Context, pkt []byte, privateKey *ecdsa.PrivateKey) (*models.LogEntryAnon, error) {
	pubCert, err := createX509Cert("subject", pkt, privateKey)
	if err != nil {
		return nil, fmt.Errorf("Error creating x509 cert: %w", err)
	}

	// generate signature
	hasher := sha256.New()
	hasher.Write(pkt)
	var hash []byte
	hash = hasher.Sum(hash)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("Error generating signature: %w", err)
	}
	signature, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		return nil, fmt.Errorf("Error encoding signature: %w", err)
	}

	rekorClient, err := rclient.GetRekorClient(RekorURL)
	if err != nil {
		return nil, fmt.Errorf("Error creating rekor client: %w", err)
	}

	entry, err := cosign.TLogUpload(ctx, rekorClient, signature, hasher, pubCert)
	if err != nil {
		return nil, fmt.Errorf("Error uploading tlog: %w", err)
	}
	return entry, nil
}

func createX509Cert(subject string, pkt []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	pubKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("Error marshalling public key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber:            big.NewInt(1),
		Subject:                 pkix.Name{CommonName: subject},
		RawSubjectPublicKeyInfo: pubKey,
		NotBefore:               time.Now(),
		NotAfter:                time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:                x509.KeyUsageDigitalSignature,
		ExtKeyUsage:             []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid:   true,
		DNSNames:                []string{subject},
		IsCA:                    false,
		SubjectKeyId:            pkt,
	}

	// Create a self-signed X.509 certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("Error creating X.509 certificate: %w", err)
	}
	certBlock := &pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	return pem.EncodeToMemory(certBlock), nil
}
