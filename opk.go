package signedattestation

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/openpubkey/openpubkey/parties"
	"github.com/openpubkey/openpubkey/pktoken"
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

	tokSigner, err := pktoken.NewSigner("", "ES256", true, map[string]any{"att": hashHex})
	if err != nil {
		return nil, fmt.Errorf("error creating PK token signer: %w", err)
	}
	opkClient := parties.OpkClient{Op: sv.provider, Signer: tokSigner}

	opkSig, err := opkClient.OidcAuth()
	if err != nil {
		return nil, fmt.Errorf("error getting PK token: %w", err)
	}

	return opkSig, nil
}

func (sv *opkSignerVerifier) Verify(ctx context.Context, data, sig []byte) error {
	cicClaims, err := sv.provider.VerifyPKToken(sig, nil)
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
