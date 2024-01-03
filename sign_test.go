package signedattestation

import (
	"context"
	"crypto"
	"testing"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/openpubkey/openpubkey/client/providers"
	"github.com/openpubkey/openpubkey/pktoken"
)

const (
	USE_MOCK_TL = true
)

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
		tl = &MockTL{
			UploadLogEntryFunc: func(ctx context.Context, pkToken *pktoken.PKToken, payload []byte, signature []byte, signer crypto.Signer) ([]byte, error) {
				return []byte(""), nil
			},
			VerifyLogEntryFunc: func(ctx context.Context, entryBytes []byte) error {
				return nil
			},
			VerifyEntryPayloadFunc: func(entryBytes, payload, pkToken []byte) error {
				return nil
			},
		}
	} else {
		tl = &RekorTL{}
	}

	ctx := context.WithValue(context.Background(), TlCtxKey(DefaultCtxKey), tl)
	env, err := SignInTotoStatementExt(ctx, stmt, provider)
	if err != nil {
		t.Fatal(err)
	}

	_, err = VerifyInTotoEnvelopeExt(ctx, env, provider)
	if err != nil {
		t.Fatal(err)
	}
}
