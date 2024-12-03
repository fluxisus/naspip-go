package paseto

import (
	"strings"
	"testing"
)

func Test(t *testing.T) {

}

// "Should create private/public key pair"
func TestGenerateKey(t *testing.T) {
	keys, err := GenerateKey("public", "paserk")

	if err != nil || !strings.HasPrefix(keys["publicKey"], "k4.public.") || !strings.HasPrefix(keys["secretKey"], "k4.secret.") {
		t.Errorf("TestCreateKeys FAIL --> %v, publicKey: %s, secretKey: %s", err, keys["publicKey"], keys["secretKey"])
	}
}

//   test("Should decode token", async () => {
//     const decoded = paseto.decode(pasetoToken);

//     expect(decoded).toBeDefined();
//     expect(decoded.version).toBe("v4");
//     expect(decoded.purpose).toBe("public");
//     expect(decoded.footer).toBeUndefined();
//     expect(decoded.payload?.iat).toBeDefined();
//   });

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

//   test("Should not verify a token with wrong issuer domain", async () => {
//     expect(async () => {
//       await paseto.verify(pasetoToken, commonKeys.publicKey, {
//         issuer: "not-issuer-domain",
//       });
//     }).rejects.toThrow("issuer mismatch");
//   });
