package paseto

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var keys = map[string]string{
	"publicKey": "k4.public.sGVse4eAyt6ycfmkKl3Az7RxB34nklDPgKbNLvxVwlk",
	"secretKey": "k4.secret.y4-gze54dwfLR0eyxiJL2mRicZr6SX2-xIn6kgo999iwZWx7h4DK3rJx-aQqXcDPtHEHfieSUM-Aps0u_FXCWQ",
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

	token := "v4.public.eyJwYXlsb2FkIjp7InBheW1lbnQiOnsiaWQiOiJ5b3VyLXVuaXF1ZS1pZCIsImFkZHJl" +
		"c3MiOiJURXJRMUxUekZqTmZzd3RIY2dCclF3OHZkNHFYRFRack5QIiwibmV0d29yayI6IlRST04iLCJjb2luIjoi" +
		"VFI3TkhxamVLUXhHVENpOHE4Wlk0cEw4b3RTemdqTGo2dCIsImlzX29wZW4iOmZhbHNlLCJhbW91bnQiOiIxMC4y" +
		"NSJ9LCJvcmRlciI6eyJ0b3RhbF9hbW91bnQiOiIxMjUwMDAiLCJjb2luX2NvZGUiOiJBUlMiLCJtZXJjaGFudCI6" +
		"eyJuYW1lIjoiWW91ciBFY29tbWVyY2UiLCJkZXNjcmlwdGlvbiI6IkVjb21tZXJjZSIsInRheF9pZCI6IjExMjUz" +
		"Njk4NTQ3In0sIml0ZW1zIjpbeyJ0aXRsZSI6Ikl0ZW0xIiwiZGVzY3JpcHRpb24iOiJEZXNjcmlwdGlvbiBJdGVt" +
		"IDEiLCJhbW91bnQiOiIyNTAwMCIsInVuaXRfcHJpY2UiOiIyNTAwMCIsInF1YW50aXR5IjoxLCJjb2luX2NvZGUi" +
		"OiJBUlMifSx7InRpdGxlIjoiSXRlbTIiLCJkZXNjcmlwdGlvbiI6IkRlc2NyaXB0aW9uIEl0ZW0gMiIsImFtb3Vu" +
		"dCI6IjEwMDAwMCIsInVuaXRfcHJpY2UiOiI1MDAwIiwicXVhbnRpdHkiOjIwLCJjb2luX2NvZGUiOiJBUlMifV19" +
		"fSwia2lkIjoiazQiLCJraXMiOiJodHRwczovL3N0ZC1wYXl3YXZlLmNvbSIsImtlcCI6IjIwMjUtMTItMDhUMjI6" +
		"Mjc6MjAuMDA5WiIsImlhdCI6IjIwMjQtMTItMDhUMjI6Mjc6MjAuMDEyWiIsImV4cCI6IjIwMjQtMTItMDhUMjM6" +
		"Mjc6MjAuMDEyWiIsImlzcyI6Imh0dHBzOi8vYnVzc2luZXMucGF5bWVudHMuY29tIn0Fej2QPTbuJAV1Qm_vjW9d" +
		"oRJTla66YohQt7-COQLZZNbyHjpd_XGB4wQvft980kf7LrjSN30yIktD017N3OID"

	decoded, err := DecodeV4(token)

	if err != nil {
		t.Errorf("TestDecode FAIL --> %v", err)
	}

	assert.Equal("v4", decoded.Version)
	assert.Equal("public", decoded.Purpose)
	assert.Equal([]byte{}, decoded.Footer)
	assert.Equal("2024-12-08T22:27:20.012Z", decoded.Payload.Iat)
}

//   test("Should sign token and verify it", async () => {
//     const signed = await paseto.sign(
//       {
//         payload: "test",
//       },
//       commonKeys.secretKey,
//     );

//     const verified = await paseto.verify(signed, commonKeys.publicKey);

//     expect(signed).toBeDefined();
//     expect(verified).toBeDefined();
//     expect(verified.payload).toBe("test");
//   });

//   test("Should fail to sign and retrieve a token", async () => {
//     expect(async () => {
//       await paseto.sign(
//         {
//           payload: "test",
//         },
//         "not-secret-key",
//       );
//     }).rejects.toThrow("invalid key provided");
//   });

//   test("Should not verify a token with wrong public key", async () => {
//     expect(async () => {
//       await paseto.verify(pasetoToken, "not-public-key");
//     }).rejects.toThrow("invalid key provided");
//   });

//   test("Should not verify a token with wrong token format", async () => {
//     expect(async () => {
//       await paseto.verify("not-token", commonKeys.publicKey);
//     }).rejects.toThrow("token is not a v4.public PASETO");
//   });

//   test("Should not verify a token with expired time", async () => {
//     const expiredToken = await paseto.sign(
//       {
//         payload: "test",
//       },
//       commonKeys.secretKey,
//       { expiresIn: "0s" },
//     );

//     expect(async () => {
//       await paseto.verify(expiredToken, commonKeys.publicKey);
//     }).rejects.toThrow("token is expired");
//   });

// Should not verify a token with wrong iss
func Test(t *testing.T) {
	// expect(async () => {
	//   await paseto.verify(pasetoToken, commonKeys.publicKey, {
	//     issuer: "not-issuer-domain",
	//   });
	// }).rejects.toThrow("issuer mismatch");
}
