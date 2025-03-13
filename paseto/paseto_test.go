package paseto

import (
	"strings"
	"testing"
	"time"

	"github.com/fluxisus/naspip-go/v3/encoding/protobuf"
	"github.com/fluxisus/naspip-go/v3/utils"
	"github.com/stretchr/testify/assert"
)

var keys = map[string]string{
	"publicKey":      "k4.public.sGVse4eAyt6ycfmkKl3Az7RxB34nklDPgKbNLvxVwlk",
	"secretKey":      "k4.secret.y4-gze54dwfLR0eyxiJL2mRicZr6SX2-xIn6kgo999iwZWx7h4DK3rJx-aQqXcDPtHEHfieSUM-Aps0u_FXCWQ",
	"otherPublicKey": "k4.public.I1bDM2T-nlLuo_HDCCt_0-Y5-f80VZ82-uuYFyHYuqI",
	"otherSecretKey": "k4.secret.7TKiFPW-8SPF1CRHl74sx-bCrGhcH74b621Ac7S5h0MjVsMzZP6eUu6j8cMIK3_T5jn5_zRVnzb665gXIdi6og",
}

// Should create private/public key pair
func TestGenerateKey(t *testing.T) {
	keys, err := GenerateKey("public", "paserk")

	if err != nil || !strings.HasPrefix(keys["publicKey"], "k4.public.") || !strings.HasPrefix(keys["secretKey"], "k4.secret.") {
		t.Errorf("TestCreateKeys FAIL --> %v, publicKey: %s, secretKey: %s", err, keys["publicKey"], keys["secretKey"])
	}
}

// Should decode token
func TestDecode(t *testing.T) {
	assert := assert.New(t)

	issuedAt := "2024-12-08T22:27:20.012Z"
	var handler = PasetoV4Handler{}
	var payload = protobuf.PasetoTokenData{
		Kis: "test-kis",
		Data: &protobuf.PasetoTokenData_InstructionPayload{
			InstructionPayload: &protobuf.InstructionPayload{
				Payment: &protobuf.PaymentInstruction{
					Id: "test-id",
				},
			},
		},
	}

	payloadBytes, _ := protobuf.EncodeProto(&payload)

	options := PasetoSignOptions{
		Issuer:    "test-issuer.com",
		KeyId:     "test-kid",
		ExpiresIn: "1h",
		IssuedAt:  issuedAt,
	}

	token, _ := handler.Sign(payloadBytes, keys["secretKey"], options)

	decoded, err := DecodeV4(token)

	if err != nil {
		t.Errorf("TestDecode FAIL --> %v", err)
	}

	assert.Equal("v4", decoded.Version)
	assert.Equal("public", decoded.Purpose)
	assert.Equal([]byte{}, decoded.Footer)
	assert.Equal(issuedAt, decoded.Payload.Iat)
}

// Should sign token and verify it
func TestSingAndVerify(t *testing.T) {
	assert := assert.New(t)

	var handler = PasetoV4Handler{}
	var payload = protobuf.PasetoTokenData{
		Data: &protobuf.PasetoTokenData_InstructionPayload{
			InstructionPayload: &protobuf.InstructionPayload{
				Payment: &protobuf.PaymentInstruction{
					Id: "test-id",
				},
			},
		},
	}

	payloadBytes, _ := protobuf.EncodeProto(&payload)

	token, errSign := handler.Sign(payloadBytes, keys["secretKey"], PasetoSignOptions{ExpiresIn: "1h"})

	if errSign != nil {
		t.Errorf("TestSingAndVerify Sign FAIL --> %v", errSign)
	}

	verified, err := handler.Verify(token, keys["publicKey"], PasetoVerifyOptions{})

	if err != nil {
		t.Errorf("TestDecode FAIL --> %v, %v", err, token)
	}

	assert.Equal(payload.GetInstructionPayload().Payment.Id, verified.Payload.Data["payment"].(map[string]interface{})["id"])
}

// Should fail to sign without a valid secret key
func TestFailSingWithoutValidSecret(t *testing.T) {

	var handler = PasetoV4Handler{}
	var payload = protobuf.PasetoTokenData{
		Data: &protobuf.PasetoTokenData_InstructionPayload{
			InstructionPayload: &protobuf.InstructionPayload{
				Payment: &protobuf.PaymentInstruction{
					Id: "test-id",
				},
			},
		},
	}

	payloadBytes, _ := protobuf.EncodeProto(&payload)

	assert.Panics(t, func() { handler.Sign(payloadBytes, "not-secret-key", PasetoSignOptions{}) }, "The code panics")
}

// Should not verify a token with wrong public key
func TestFailVerifyWithWrongPublicKey(t *testing.T) {
	assert := assert.New(t)

	var handler = PasetoV4Handler{}
	var payload = protobuf.PasetoTokenData{
		Data: &protobuf.PasetoTokenData_UrlPayload{
			UrlPayload: &protobuf.UrlPayload{
				Url: "test-url",
			},
		},
	}

	payloadBytes, _ := protobuf.EncodeProto(&payload)

	token, _ := handler.Sign(payloadBytes, keys["secretKey"], PasetoSignOptions{})

	verified, err := handler.Verify(token, keys["otherPublicKey"], PasetoVerifyOptions{})

	assert.Nil(verified)
	assert.EqualError(err, "paseto: invalid token signature")
}

// Should not verify a token with wrong token format
func TestFailVerifyInvalidTokenFormat(t *testing.T) {
	assert := assert.New(t)

	var handler = PasetoV4Handler{}

	verified, err := handler.Verify("not-token", keys["publicKey"], PasetoVerifyOptions{})

	assert.Nil(verified)
	assert.EqualError(err, "paseto: invalid token")
}

// Should not verify a token with expired time
func TestExpiredToken(t *testing.T) {
	assert := assert.New(t)

	var handler = PasetoV4Handler{}
	var payload = protobuf.PasetoTokenData{
		Data: &protobuf.PasetoTokenData_InstructionPayload{
			InstructionPayload: &protobuf.InstructionPayload{
				Payment: &protobuf.PaymentInstruction{
					Id: "test-id",
				},
			},
		},
	}

	payloadBytes, _ := protobuf.EncodeProto(&payload)

	token, _ := handler.Sign(payloadBytes, keys["secretKey"], PasetoSignOptions{ExpiresIn: "0s"})

	verified, err := handler.Verify(token, keys["publicKey"], PasetoVerifyOptions{})

	assert.Nil(verified)
	assert.EqualError(err, "token is expired")
}

// Should not verify a token with expired by max age
func TestInvalidTokenByMaxAge(t *testing.T) {
	assert := assert.New(t)

	var handler = PasetoV4Handler{}
	var payload = protobuf.PasetoTokenData{
		Data: &protobuf.PasetoTokenData_InstructionPayload{
			InstructionPayload: &protobuf.InstructionPayload{
				Payment: &protobuf.PaymentInstruction{
					Id: "test-id",
				},
			},
		},
	}

	payloadBytes, _ := protobuf.EncodeProto(&payload)

	issuedAt := time.Now().UTC().Add(-1000 * time.Hour).Format(utils.RFC3339Mili)

	token, _ := handler.Sign(payloadBytes, keys["secretKey"], PasetoSignOptions{IssuedAt: issuedAt, ExpiresIn: "10000h"})

	verified, err := handler.Verify(token, keys["publicKey"], PasetoVerifyOptions{MaxTokenAge: "100h"})

	assert.Nil(verified)
	assert.EqualError(err, "maxTokenAge exceeded")
}

// Should not verify a token after not before at time
func TestInvalidTokenByNbf(t *testing.T) {
	assert := assert.New(t)

	var handler = PasetoV4Handler{}
	var payload = protobuf.PasetoTokenData{
		Data: &protobuf.PasetoTokenData_InstructionPayload{
			InstructionPayload: &protobuf.InstructionPayload{
				Payment: &protobuf.PaymentInstruction{
					Id: "test-id",
				},
			},
		},
	}

	payloadBytes, _ := protobuf.EncodeProto(&payload)

	token, _ := handler.Sign(payloadBytes, keys["secretKey"], PasetoSignOptions{NotBefore: "1h"})

	verified, err := handler.Verify(token, keys["publicKey"], PasetoVerifyOptions{})

	assert.Nil(verified)
	assert.EqualError(err, "token is not active yet")
}

// Should not verify a token after not before at time
func TestIssuedAt(t *testing.T) {
	assert := assert.New(t)

	var handler = PasetoV4Handler{}
	var payload = protobuf.PasetoTokenData{
		Data: &protobuf.PasetoTokenData_InstructionPayload{
			InstructionPayload: &protobuf.InstructionPayload{
				Payment: &protobuf.PaymentInstruction{
					Id: "test-id",
				},
			},
		},
	}

	payloadBytes, _ := protobuf.EncodeProto(&payload)

	token, _ := handler.Sign(payloadBytes, keys["secretKey"], PasetoSignOptions{IssuedAt: "2024-12-11T15:11:11Z", ExpiresIn: "10h", NotBefore: "1h"})

	decoded, _ := DecodeV4(token)

	assert.Equal("2024-12-11T15:11:11Z", decoded.Payload.Iat)
	assert.Equal("2024-12-11T16:11:11Z", decoded.Payload.Nbf)
	assert.Equal("2024-12-12T01:11:11Z", decoded.Payload.Exp)
}

// Should not verify a token with wrong iss and ignore expiration
func TestWrongIssuer(t *testing.T) {

	assert := assert.New(t)

	var handler = PasetoV4Handler{}
	var payload = protobuf.PasetoTokenData{
		Data: &protobuf.PasetoTokenData_InstructionPayload{
			InstructionPayload: &protobuf.InstructionPayload{
				Payment: &protobuf.PaymentInstruction{
					Id: "test-id",
				},
			},
		},
	}

	payloadBytes, _ := protobuf.EncodeProto(&payload)

	token, _ := handler.Sign(payloadBytes, keys["secretKey"], PasetoSignOptions{IssuedAt: "2024-12-11T15:11:11Z", ExpiresIn: "1h", Issuer: "test-issuer"})

	verified, err := handler.Verify(token, keys["publicKey"], PasetoVerifyOptions{Issuer: "not-same-issuer"})

	assert.Nil(verified)
	assert.EqualError(err, "issuer mismatch")
}

// Should not verify a token with wrong aud
func TestWrongAudience(t *testing.T) {

	assert := assert.New(t)

	var handler = PasetoV4Handler{}
	var payload = protobuf.PasetoTokenData{
		Data: &protobuf.PasetoTokenData_InstructionPayload{
			InstructionPayload: &protobuf.InstructionPayload{
				Payment: &protobuf.PaymentInstruction{
					Id: "test-id",
				},
			},
		},
	}

	payloadBytes, _ := protobuf.EncodeProto(&payload)

	token, _ := handler.Sign(payloadBytes, keys["secretKey"], PasetoSignOptions{
		IssuedAt:  "2024-12-11T15:11:11Z",
		ExpiresIn: "1h",
		Issuer:    "test-issuer",
		Audience:  "test-audience",
	})

	verified, err := handler.Verify(token, keys["publicKey"], PasetoVerifyOptions{Issuer: "test-issuer", Audience: "wrong-audience"})

	assert.Nil(verified)
	assert.EqualError(err, "audience mismatch")
}

// Should not verify a token with wrong aud
func TestVerifyWithAssertion(t *testing.T) {

	assert := assert.New(t)

	var handler = PasetoV4Handler{}
	var payload = protobuf.PasetoTokenData{
		Data: &protobuf.PasetoTokenData_InstructionPayload{
			InstructionPayload: &protobuf.InstructionPayload{
				Payment: &protobuf.PaymentInstruction{
					Id: "test-id",
				},
			},
		},
	}

	payloadBytes, _ := protobuf.EncodeProto(&payload)

	token, _ := handler.Sign(payloadBytes, keys["secretKey"], PasetoSignOptions{
		ExpiresIn: "1h",
		Issuer:    "test-issuer",
		Audience:  "test-audience",
		Assertion: []byte(keys["publicKey"]),
	})

	verified, _ := handler.Verify(token, keys["publicKey"], PasetoVerifyOptions{Issuer: "test-issuer", Audience: "test-audience", Assertion: []byte(keys["publicKey"])})

	assert.Equal("test-issuer", verified.Payload.Iss)
	assert.Equal("test-audience", verified.Payload.Aud)
	assert.Equal(payload.GetInstructionPayload().Payment.Id, verified.Payload.Data["payment"].(map[string]interface{})["id"])
}
