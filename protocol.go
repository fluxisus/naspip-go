package main

import (
	"encoding/json"
	"fmt"
	"log"

	"crypto-payments-standard-protocol/paseto"
)

func PaymentInstructionsBuilder(name string) string {
	message := fmt.Sprintf("Hi, %v. Welcome!", name)
	return message
}

func main() {
	keys, error := paseto.GenerateKey("public", "paserk")

	if error != nil {
		log.Fatal(error)
	}

	fmt.Println(keys)

	// fmt.Println(paseto.GetPrivateKey(keys["secretKey"]))
	// fmt.Println(paseto.GetPublicKey(keys["publicKey"]))

	// fmt.Println(time.Now().UTC().Format(time.RFC3339))

	var payload = map[string]any{"pepe": 2, "mengano": "sultano"}

	payloadString, _ := json.Marshal(payload)

	options := paseto.SignOptions{
		Kid:       "pepito",
		ExpiresIn: "1h",
	}

	token, err := paseto.Sign(string(payloadString), keys["secretKey"], options)

	if err != nil {
		panic(err)
	}

	verifyToken, err := paseto.Verify(token, keys["publicKey"])

	if err != nil {
		panic(err)
	}

	fmt.Println(token)

	fmt.Println(verifyToken)

	fmt.Println(paseto.Decode(token))

}
