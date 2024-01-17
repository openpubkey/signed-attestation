package signedattestation

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/openpubkey/openpubkey/client/providers"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/sigstore/rekor/pkg/generated/models"
)

const (
	USE_MOCK_TL = true
)

func GetMockTL() TL {
	return &MockTL{
		UploadLogEntryFunc: func(ctx context.Context, pkToken *pktoken.PKToken, payload []byte, signature []byte, signer crypto.Signer) ([]byte, error) {
			return []byte(TestEntry), nil
		},
		VerifyLogEntryFunc: func(ctx context.Context, entryBytes []byte) error {
			return nil
		},
		VerifyEntryPayloadFunc: func(entryBytes, payload, pkToken []byte) error {
			return nil
		},
		UnmarshalEntryFunc: func(entry []byte) (any, error) {
			le := new(models.LogEntryAnon)
			err := le.UnmarshalBinary(entry)
			if err != nil {
				return nil, fmt.Errorf("error failed to unmarshal TL entry: %w", err)
			}
			return le, nil
		},
	}
}

func TestSignAndVerify(t *testing.T) {
	stmt := in_toto.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: in_toto.PredicateSPDX,
		},
		Predicate: "test",
	}

	var err error
	provider, err := providers.NewMockOpenIdProvider()
	if err != nil {
		t.Fatal(err)
	}
	env, err := SignInTotoStatement(context.Background(), stmt, provider)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyInTotoEnvelope(context.Background(), env, provider)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignAndVerifyExt(t *testing.T) {
	stmt := in_toto.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: in_toto.PredicateSPDX,
		},
		Predicate: "test",
	}

	var err error
	provider, err := providers.NewMockOpenIdProvider()
	if err != nil {
		t.Fatal(err)
	}

	var tl TL
	if USE_MOCK_TL {
		tl = GetMockTL()
	} else {
		tl = &RekorTL{}
	}

	ctx := WithTL(context.Background(), tl)
	env, err := SignInTotoStatementExt(ctx, stmt, provider)
	if err != nil {
		t.Fatal(err)
	}

	serializedEnv, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	deserializedEnv := new(Envelope)
	err = json.Unmarshal(serializedEnv, deserializedEnv)
	if err != nil {
		t.Fatal(err)
	}

	_, err = VerifyInTotoEnvelopeExt(ctx, deserializedEnv, provider)
	if err != nil {
		t.Fatal(err)
	}
}
