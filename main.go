package main

import (
	"fmt"

	"crypto-payments-standard-protocol/paseto"
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

	fmt.Println(keys)

	// fmt.Println(paseto.GetPrivateKey(keys["secretKey"]))
	// fmt.Println(paseto.GetPublicKey(keys["publicKey"]))

	// fmt.Println(time.Now().UTC().Format(time.RFC3339))
	qrCrypto := "qr-crypto.v4.public.eyJwYXlsb2FkIjp7InBheW1lbnQiOnsiaWQiOiJpZCIsImFkZHJlc3MiOiJzdHJpbmciLCJuZXR3b3JrIjoiVFJPTiIsImNvaW4iOiJUUjdOSHFqZUtReEdUQ2k4cThaWTRwTDhvdFN6Z2pMajZ0IiwiaXNfb3BlbiI6ZmFsc2UsImFtb3VudCI6IjEifSwib3JkZXIiOnsidG90YWxfYW1vdW50IjoiMSIsImNvaW5fY29kZSI6IlRSN05IcWplS1F4R1RDaThxOFpZNHBMOG90U3pnakxqNnQiLCJpdGVtcyI6W3sidGl0bGUiOiJpdGVtTmFtZSIsImNvaW5fY29kZSI6IlRSN05IcWplS1F4R1RDaThxOFpZNHBMOG90U3pnakxqNnQiLCJhbW91bnQiOiIxIiwicXVhbnRpdHkiOjF9XSwibWVyY2hhbnQiOnsibmFtZSI6Im1lcmNoYW50TmFtZSJ9fX0sImtpZCI6ImtleS1pZC1vbmUiLCJraXMiOiJ0ZXN0aW5nLmNvbSIsImtlcCI6IjFoIiwiaWF0IjoiMjAyNC0xMi0wM1QwMTo1ODo0NC40NTdaIiwiZXhwIjoiMjAyNC0xMi0wM1QwMjo1ODo0NC40NTdaIiwiaXNzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSJ9jY4wYEauQu4yZBFr7ddd0_7pv8SoLCK9_vjMZgGWzOkzd_qFgRZOSUnh8sHfQjtWoIu1hekQPWfswWRLZ5nwBA"
	token := "v4.public.eyJwYXlsb2FkIjp7InBheW1lbnQiOnsiaWQiOiJpZCIsImFkZHJlc3MiOiJzdHJpbmciLCJuZXR3b3JrIjoiVFJPTiIsImNvaW4iOiJUUjdOSHFqZUtReEdUQ2k4cThaWTRwTDhvdFN6Z2pMajZ0IiwiaXNfb3BlbiI6ZmFsc2UsImFtb3VudCI6IjEifSwib3JkZXIiOnsidG90YWxfYW1vdW50IjoiMSIsImNvaW5fY29kZSI6IlRSN05IcWplS1F4R1RDaThxOFpZNHBMOG90U3pnakxqNnQiLCJpdGVtcyI6W3sidGl0bGUiOiJpdGVtTmFtZSIsImNvaW5fY29kZSI6IlRSN05IcWplS1F4R1RDaThxOFpZNHBMOG90U3pnakxqNnQiLCJhbW91bnQiOiIxIiwicXVhbnRpdHkiOjF9XSwibWVyY2hhbnQiOnsibmFtZSI6Im1lcmNoYW50TmFtZSJ9fX0sImtpZCI6ImtleS1pZC1vbmUiLCJraXMiOiJ0ZXN0aW5nLmNvbSIsImtlcCI6IjFoIiwiaWF0IjoiMjAyNC0xMi0wM1QwMTo1ODo0NC40NTdaIiwiZXhwIjoiMjAyNC0xMi0wM1QwMjo1ODo0NC40NTdaIiwiaXNzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSJ9jY4wYEauQu4yZBFr7ddd0_7pv8SoLCK9_vjMZgGWzOkzd_qFgRZOSUnh8sHfQjtWoIu1hekQPWfswWRLZ5nwBA"

	var handler = paseto.PasetoV4Handler{}
	// var payload = map[string]any{"payload": map[string]any{"pepe": 2, "mengano": "sultano"}, "kis": "ariel"}

	// payloadString, _ := json.Marshal(payload)

	// options := paseto.PasetoSignOptions{
	// 	KeyId:     "pepito",
	// 	ExpiresIn: "1h",
	// }

	// token, err := handler.Sign(string(payloadString), keys["secretKey"], options)

	// if err != nil {
	// 	panic(err)
	// }

	var cryptoHandler = PaymentInstructionsBuilder{PasetoHandler: handler}
	var options = QrCriptoReadOptions{IgnoreKeyExp: true}

	payment, errPayment := cryptoHandler.Read(qrCrypto, keys["publicKey"], options)

	if errPayment != nil {
		panic(errPayment)
	}

	verifyToken, err := handler.Verify(token, keys["publicKey"])

	if err != nil {
		panic(err)
	}

	fmt.Println(token)
	fmt.Println(paseto.DecodeV4(token))

	fmt.Println("Verify token", verifyToken.Payload.Kid)

	fmt.Println(payment)

}
