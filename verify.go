package signedattestation

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/go-openapi/strfmt"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/rekor/pkg/generated/models"
)

func VerifyInTotoEnvelope(ctx context.Context, env *dsse.Envelope, provider client.OpenIdProvider) (*intoto.Statement, error) {

	s, err := dsse.NewEnvelopeVerifier(NewOPKSignerVerifier(provider))
	if err != nil {
		return nil, fmt.Errorf("failed to create dsse envelope verifier: %w", err)
	}

	// enforce payload type
	if env.PayloadType != intoto.PayloadType {
		return nil, fmt.Errorf("unsupported payload type %s", env.PayloadType)
	}

	_, err = s.Verify(ctx, env)
	if err != nil {
		return nil, fmt.Errorf("failed to verify dsse envelope: %w", err)
	}

	stmt := new(intoto.Statement)
	stmtBytes, err := env.DecodeB64Payload()
	if err != nil {
		return nil, fmt.Errorf("failed to decode in-toto statement: %w", err)
	}
	err = json.Unmarshal(stmtBytes, stmt)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal in-toto statement: %w", err)
	}

	return stmt, nil
}

func VerifyInTotoEnvelopeExt(ctx context.Context, env *Envelope, provider client.OpenIdProvider) (*intoto.Statement, error) {

	// enforce payload type
	if env.PayloadType != intoto.PayloadType {
		return nil, fmt.Errorf("unsupported payload type %s", env.PayloadType)
	}

	// verify signatures and transparency log entry
	verifier := NewOPKSignerVerifier(provider)
	for _, sig := range env.Signatures {
		if sig.Extension.Kind == OpkSignatureID {
			// verify opk signature
			payload, err := base64.RawStdEncoding.DecodeString(env.Payload)
			if err != nil {
				return nil, fmt.Errorf("error failed to decode OPK payload: %w", err)
			}
			encPayload := dsse.PAE(intoto.PayloadType, payload)
			pkToken := sig.Extension.Ext["pkt"].([]byte)
			err = verifier.Verify(ctx, encPayload, pkToken)
			if err != nil {
				return nil, fmt.Errorf("error failed to verify PK token: %w", err)
			}

			// verify payload ephemeral ecdsa signature
			ok, err := VerifyPayloadSignature(ctx, pkToken, encPayload, sig.Sig)
			if !ok {
				return nil, fmt.Errorf("error failed to verify payload signature: %w", err)
			}

			// verify TL entry
			entry := new(models.LogEntryAnon)
			err = entry.UnmarshalBinary(sig.Extension.Ext["tl"].([]byte))
			if err != nil {
				return nil, fmt.Errorf("error failed to unmarshal TL entry: %w", err)
			}
			err = entry.Verification.Validate(strfmt.Default)
			if err != nil {
				return nil, fmt.Errorf("TL entry failed validation: %w", err)
			}
		}
	}

	// decode in-toto statement
	stmt := new(intoto.Statement)
	stmtBytes, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode in-toto statement: %w", err)
	}
	err = json.Unmarshal(stmtBytes, stmt)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal in-toto statement: %w", err)
	}
	return stmt, nil
}

// VerifyPayloadSignature extracts the ephemeral ecdsa public key from a PK token and verifies the provided signature
func VerifyPayloadSignature(ctx context.Context, pkToken []byte, payload []byte, signature string) (bool, error) {
	token := &pktoken.PKToken{}
	err := json.Unmarshal(pkToken, token)
	if err != nil {
		return false, fmt.Errorf("error unmarshalling PK token from JSON: %w", err)
	}
	cic, err := token.Cic.ProtectedHeaders().AsMap(ctx)
	if err != nil {
		return false, fmt.Errorf("error getting CIC protected headers: %w", err)
	}
	cicClaims, err := clientinstance.ParseClaims(cic)
	if err != nil {
		return false, fmt.Errorf("error failed to parse cic: %w", err)
	}
	decodedSig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("error failed to decode signature: %w", err)
	}
	ecPub := new(ecdsa.PublicKey)
	err = cicClaims.PublicKey().Raw(ecPub)
	if err != nil {
		return false, fmt.Errorf("error failed to get public key from cic: %w", err)
	}
	return ecdsa.VerifyASN1(ecPub, s256(payload), decodedSig), nil
}
