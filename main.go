package main

import (
	"crypto-payments-standard-protocol/paseto"
	"fmt"
)

func main() {
	// keys, error := paseto.GenerateKey("public", "paserk")

	// if error != nil {
	// 	log.Fatal(error)
	// }

	keys := map[string]string{
		"publicKey": "k4.public.sGVse4eAyt6ycfmkKl3Az7RxB34nklDPgKbNLvxVwlk",
		"secretKey": "k4.secret.y4-gze54dwfLR0eyxiJL2mRicZr6SX2-xIn6kgo999iwZWx7h4DK3rJx-aQqXcDPtHEHfieSUM-Aps0u_FXCWQ",
	}

	// fmt.Println(paseto.GetPrivateKey(keys["secretKey"]))
	// fmt.Println(paseto.GetPublicKey(keys["publicKey"]))

	// fmt.Println(time.Now().UTC().Format(time.RFC3339))
	// qrCrypto := "qr-crypto.v4.public.eyJwYXlsb2FkIjp7InBheW1lbnQiOnsiaWQiOiJpZCIsImFkZHJlc3MiOiJzdHJpbmciLCJuZXR3b3JrIjoiVFJPTiIsImNvaW4iOiJUUjdOSHFqZUtReEdUQ2k4cThaWTRwTDhvdFN6Z2pMajZ0IiwiaXNfb3BlbiI6ZmFsc2UsImFtb3VudCI6IjEifSwib3JkZXIiOnsidG90YWxfYW1vdW50IjoiMSIsImNvaW5fY29kZSI6IlRSN05IcWplS1F4R1RDaThxOFpZNHBMOG90U3pnakxqNnQiLCJpdGVtcyI6W3sidGl0bGUiOiJpdGVtTmFtZSIsImNvaW5fY29kZSI6IlRSN05IcWplS1F4R1RDaThxOFpZNHBMOG90U3pnakxqNnQiLCJhbW91bnQiOiIxIiwicXVhbnRpdHkiOjF9XSwibWVyY2hhbnQiOnsibmFtZSI6Im1lcmNoYW50TmFtZSJ9fX0sImtpZCI6ImtleS1pZC1vbmUiLCJraXMiOiJ0ZXN0aW5nLmNvbSIsImtlcCI6IjFoIiwiaWF0IjoiMjAyNC0xMi0wM1QwMTo1ODo0NC40NTdaIiwiZXhwIjoiMjAyNC0xMi0wM1QwMjo1ODo0NC40NTdaIiwiaXNzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSJ9jY4wYEauQu4yZBFr7ddd0_7pv8SoLCK9_vjMZgGWzOkzd_qFgRZOSUnh8sHfQjtWoIu1hekQPWfswWRLZ5nwBA"
	// token := "v4.public.eyJwYXlsb2FkIjp7InBheW1lbnQiOnsiaWQiOiJpZCIsImFkZHJlc3MiOiJzdHJpbmciLCJuZXR3b3JrIjoiVFJPTiIsImNvaW4iOiJUUjdOSHFqZUtReEdUQ2k4cThaWTRwTDhvdFN6Z2pMajZ0IiwiaXNfb3BlbiI6ZmFsc2UsImFtb3VudCI6IjEifSwib3JkZXIiOnsidG90YWxfYW1vdW50IjoiMSIsImNvaW5fY29kZSI6IlRSN05IcWplS1F4R1RDaThxOFpZNHBMOG90U3pnakxqNnQiLCJpdGVtcyI6W3sidGl0bGUiOiJpdGVtTmFtZSIsImNvaW5fY29kZSI6IlRSN05IcWplS1F4R1RDaThxOFpZNHBMOG90U3pnakxqNnQiLCJhbW91bnQiOiIxIiwicXVhbnRpdHkiOjF9XSwibWVyY2hhbnQiOnsibmFtZSI6Im1lcmNoYW50TmFtZSJ9fX0sImtpZCI6ImtleS1pZC1vbmUiLCJraXMiOiJ0ZXN0aW5nLmNvbSIsImtlcCI6IjFoIiwiaWF0IjoiMjAyNC0xMi0wM1QwMTo1ODo0NC40NTdaIiwiZXhwIjoiMjAyNC0xMi0wM1QwMjo1ODo0NC40NTdaIiwiaXNzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSJ9jY4wYEauQu4yZBFr7ddd0_7pv8SoLCK9_vjMZgGWzOkzd_qFgRZOSUnh8sHfQjtWoIu1hekQPWfswWRLZ5nwBA"

	var handler = paseto.PasetoV4Handler{}
	// var payload = UrlPayload{Url: "https://fluxis.us"}
	var payload = InstructionPayload{
		Payment: PaymentInstruction{
			Id:      "unique-id",
			Network: "TRON",
			Address: "alsdkajhsdlkasdjakl",
			Coin:    "asdasdasdads",
			Amount:  "10",
		},
	}
	var assertion = []byte(keys["publicKey"])

	var cryptoHandler = PaymentInstructionsBuilder{PasetoHandler: handler}

	// payloadString, _ := json.Marshal(payload)

	options := paseto.PasetoSignOptions{
		Issuer:    "test-issuer.com",
		KeyId:     "test-kid",
		ExpiresIn: "1h",
		Assertion: assertion,
	}

	// qrCrypto, errToken := cryptoHandler.CreateUrlPayload(payload, keys["secretKey"],
	// QrCriptoCreateOptions{SignOptions: options, KeyIssuer: "test-key", KeyExpiration: "2025-12-12T15:10:10.000Z"})

	qrCrypto, errToken := cryptoHandler.CreatePaymentInstruction(payload, keys["secretKey"],
		QrCriptoCreateOptions{SignOptions: options, KeyIssuer: "test-key", KeyExpiration: "2025-12-12T15:10:10.000Z"})

	if errToken != nil {
		panic(errToken)
	}

	fmt.Println(qrCrypto, len(qrCrypto))

	// token, err := handler.Sign(string(payloadString), keys["secretKey"], options)

	// if err != nil {
	// 	panic(err)
	// }

	var readOptions = QrCriptoReadOptions{IgnoreKeyExp: true, VerifyOptions: paseto.PasetoVerifyOptions{IgnoreExp: true, Assertion: assertion}}

	payment, errPayment := cryptoHandler.Read(qrCrypto, keys["publicKey"], readOptions)

	if errPayment != nil {
		panic(errPayment)
	}

	// verifyToken, err := handler.Verify(token, keys["publicKey"], paseto.PasetoVerifyOptions{})

	// if err != nil {
	// 	panic(err)
	// }

	// fmt.Println(len(token))
	// fmt.Println(paseto.DecodeV4(token))

	// fmt.Println("Verify token", verifyToken.Payload.Kid)

	fmt.Println(payment)

}
