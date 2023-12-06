package signedattestation

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

type opkSignerVerifier struct {
	provider client.OpenIdProvider
}

func NewOPKSignerVerifier(provider client.OpenIdProvider) dsse.SignerVerifier {
	return &opkSignerVerifier{provider: provider}
}

func (sv *opkSignerVerifier) Sign(ctx context.Context, data []byte) ([]byte, error) {
	hash := s256(data)
	hashHex := hex.EncodeToString(hash)

	signer, err := util.GenKeyPair(jwa.ES256)
	if err != nil {
		return nil, fmt.Errorf("error generating key pair: %w", err)
	}

	opkClient := client.OpkClient{Op: sv.provider}
	pkToken, err := opkClient.OidcAuth(ctx, signer, jwa.ES256, map[string]any{"att": hashHex}, true)
	if err != nil {
		return nil, fmt.Errorf("error getting PK token: %w", err)
	}

	pkTokenJSON, err := json.Marshal(pkToken)
	if err != nil {
		return nil, fmt.Errorf("error marshalling PK token to JSON: %w", err)
	}

	return pkTokenJSON, nil
}

func (sv *opkSignerVerifier) Verify(ctx context.Context, data, sig []byte) error {
	token := &pktoken.PKToken{}
	err := json.Unmarshal(sig, token)
	if err != nil {
		return fmt.Errorf("error unmarshalling PK token from JSON: %w", err)
	}

	err = client.VerifyPKToken(ctx, token, sv.provider)
	if err != nil {
		return fmt.Errorf("error verifying PK token: %w", err)
	}
	cicPH, err := token.Cic.ProtectedHeaders().AsMap(ctx)
	if err != nil {
		return fmt.Errorf("error getting CIC protected headers: %w", err)
	}
	att, ok := cicPH["att"]
	if !ok {
		return fmt.Errorf("CIC protected headers missing att")
	}
	attStr, ok := att.(string)
	if !ok {
		return fmt.Errorf("att is not a string")
	}
	attDigest, err := hex.DecodeString(attStr)
	if err != nil {
		return fmt.Errorf("error decoding att: %w", err)
	}

	if !bytes.Equal(attDigest, s256(data)) {
		return fmt.Errorf("att does not match data")
	}

	return nil
}

func (*opkSignerVerifier) Public() crypto.PublicKey {
	return nil
}

func (*opkSignerVerifier) KeyID() (string, error) {
	return "OPK", nil
}

func s256(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
