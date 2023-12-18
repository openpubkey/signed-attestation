package signedattestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/go-openapi/strfmt"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/openpubkey/openpubkey/client"
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

	entry := new(models.LogEntryAnon)
	for _, sig := range env.Signatures {
		if sig.Extension.Kind == "OPK" {
			// verify opk signature

			// verify TL entry
			err := entry.UnmarshalBinary(sig.Extension.Ext["tl"].([]byte))
			if err != nil {
				return nil, fmt.Errorf("error failed to unmarshal TL entry: %w", err)
			}
			err = entry.Verification.Validate(strfmt.Default)
			if err != nil {
				return nil, fmt.Errorf("TL entry failed validation: %w", err)
			}
		}
	}

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
