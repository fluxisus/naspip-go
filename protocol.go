package main

import (
	"fmt"
	"log"
)

func PaymentInstructionsBuilder(name string) string {
	message := fmt.Sprintf("Hi, %v. Welcome!", name)
	return message
}

func main() {
	keys, error := GenerateKey("public", "paserk")

	if error != nil {
		log.Fatal(error)
	}
	fmt.Println(keys["publicKey"])
	fmt.Println(keys["secretKey"])
}
