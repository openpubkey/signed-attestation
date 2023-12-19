package signedattestation

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/client/providers"
	"github.com/openpubkey/openpubkey/util"
)

func TestVerifyPayloadSignature(t *testing.T) {
	// generate pktoken
	signer, err := util.GenKeyPair(jwa.ES256)
	if err != nil {
		t.Fatal("error generating key pair")
	}
	provider, err := providers.NewMockOpenIdProvider()
	if err != nil {
		t.Fatal(err)
	}
	opkClient := client.OpkClient{Op: provider}
	pkToken, err := opkClient.OidcAuth(context.Background(), signer, jwa.ES256, map[string]any{}, true)
	if err != nil {
		t.Fatal("error getting PK token")
	}
	pkTokenJSON, err := json.Marshal(pkToken)
	if err != nil {
		t.Fatal("error marshalling PK token to JSON")
	}

	// sign test data
	payload := []byte("test")
	hash := s256(payload)
	sig, err := signer.Sign(rand.Reader, hash, crypto.SHA256)
	if err != nil {
		t.Fatal("failed to generate test signature")
	}

	// test verify payload signature
	valid, err := VerifyPayloadSignature(context.Background(), pkTokenJSON, payload, base64.StdEncoding.EncodeToString(sig))
	if err != nil {
		t.Fatalf("failed to verify payload signature: %s", err)
	}
	if !valid {
		t.Fatal("signature is invalid")
	}
}
