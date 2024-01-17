package signedattestation

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
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
	tl := GetTL(ctx)

	// enforce payload type
	if env.PayloadType != intoto.PayloadType {
		return nil, fmt.Errorf("unsupported payload type %s", env.PayloadType)
	}

	// verify signatures and transparency log entry
	verifier := NewOPKSignerVerifier(provider)
	for _, sig := range env.Signatures {
		if sig.Extension.Kind != OpkSignatureID {
			return nil, fmt.Errorf("error unsupported signature kind: %s", sig.Extension.Kind)
		}

		// verify opk signature
		payload, err := base64.StdEncoding.Strict().DecodeString(env.Payload)
		if err != nil {
			return nil, fmt.Errorf("error failed to decode OPK payload: %w", err)
		}
		encPayload := dsse.PAE(intoto.PayloadType, payload)
		pkTokenStr, ok := sig.Extension.Ext["pkt"].(string)
		if !ok {
			return nil, fmt.Errorf("expected pkt to be of type string, got %T", sig.Extension.Ext["pkt"])
		}
		pkToken, err := base64.StdEncoding.Strict().DecodeString(pkTokenStr)
		if err != nil {
			return nil, fmt.Errorf("error failed to decode PK token: %w", err)
		}
		err = verifier.Verify(ctx, encPayload, pkToken)
		if err != nil {
			return nil, fmt.Errorf("error failed to verify PK token: %w", err)
		}

		// verify payload ephemeral ecdsa signature
		ok, err = VerifyPayloadSignature(ctx, pkToken, encPayload, sig.Sig)
		if !ok {
			return nil, fmt.Errorf("error failed to verify payload signature: %w", err)
		}

		// verify TL entry
		entry, ok := sig.Extension.Ext["tl"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("expected tl to be of type map[string]any, got %T", sig.Extension.Ext["tl"])
		}
		entryBytes, err := json.Marshal(entry)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal TL entry: %w", err)
		}
		err = tl.VerifyLogEntry(ctx, entryBytes)
		if err != nil {
			return nil, fmt.Errorf("TL entry failed verification: %w", err)
		}

		// verify TL entry payload
		err = tl.VerifyEntryPayload(entryBytes, encPayload, pkToken)
		if err != nil {
			return nil, fmt.Errorf("TL entry failed payload verification: %w", err)
		}

	}

	// decode in-toto statement
	stmt := new(intoto.Statement)
	stmtBytes, err := base64.StdEncoding.Strict().DecodeString(env.Payload)
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
func VerifyPayloadSignature(ctx context.Context, pkToken, payload []byte, signature string) (bool, error) {
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
	decodedSig, err := base64.StdEncoding.Strict().DecodeString(signature)
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
