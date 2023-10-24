package signedattestation

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/parties"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

type opkSignerVerifier struct {
	provider parties.OpenIdProvider
}

func newOPKSignerVerifier(provider parties.OpenIdProvider) dsse.SignerVerifier {
	return &opkSignerVerifier{provider: provider}
}

func (sv *opkSignerVerifier) Sign(ctx context.Context, data []byte) ([]byte, error) {
	hash := s256(data)
	hashHex := hex.EncodeToString(hash)

	signer, err := util.GenKeyPair(jwa.ES256)
	if err != nil {
		return nil, fmt.Errorf("error generating key pair: %w", err)
	}

	opkClient := parties.OpkClient{Op: sv.provider}
	pkToken, err := opkClient.OidcAuth(signer, jwa.ES256, map[string]any{"att": hashHex}, true)
	if err != nil {
		return nil, fmt.Errorf("error getting PK token: %w", err)
	}

	pkTokenJSON, err := pkToken.ToJSON()
	if err != nil {
		return nil, fmt.Errorf("error marshalling PK token to JSON: %w", err)
	}

	return pkTokenJSON, nil
}

func (sv *opkSignerVerifier) Verify(ctx context.Context, data, sig []byte) error {
	token, err := pktoken.FromJSON(data)
	if err != nil {
		return fmt.Errorf("error unmarshalling PK token from JSON: %w", err)
	}

	cicClaims, err := sv.provider.VerifyPKToken(token, nil)
	if err != nil {
		return fmt.Errorf("error verifying PK token: %w", err)
	}

	attClaim, ok := cicClaims["att"]
	if !ok {
		return fmt.Errorf("att claim missing from CIC")
	}

	attDigestHex, ok := attClaim.(string)
	if !ok {
		return fmt.Errorf("expected att claim to be a string, got %T", attClaim)
	}

	attDigest, err := hex.DecodeString(attDigestHex)
	if err != nil {
		return fmt.Errorf("error base64-decoding att claim")
	}

	if !bytes.Equal(attDigest, s256(data)) {
		return fmt.Errorf("att claim does not match attestation digest")
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
