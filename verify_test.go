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
		t.Fatal(err)
	}
	provider, err := providers.NewMockOpenIdProvider()
	if err != nil {
		t.Fatal(err)
	}
	opkClient := client.OpkClient{Op: provider}
	pkToken, err := opkClient.OidcAuth(context.Background(), signer, jwa.ES256, map[string]any{}, true)
	if err != nil {
		t.Fatal(err)
	}
	pkTokenJSON, err := json.Marshal(pkToken)
	if err != nil {
		t.Fatal(err)
	}

	// sign test data
	payload := []byte("test")
	hash := s256(payload)
	sig, err := signer.Sign(rand.Reader, hash, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	// test verify payload signature
	valid, err := VerifyPayloadSignature(context.Background(), pkTokenJSON, payload, base64.StdEncoding.EncodeToString(sig))
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("signature is invalid")
	}
}
