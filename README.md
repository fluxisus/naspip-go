# NASPIP - Network-Agnostic Secure Payment Instructions Protocol (Go)

[![Go Reference](https://pkg.go.dev/badge/github.com/fluxisus/naspip-go/v3.svg)](https://pkg.go.dev/github.com/fluxisus/naspip-go/v3)
[![Go Report Card](https://goreportcard.com/badge/github.com/fluxisus/naspip-go/v3)](https://goreportcard.com/report/github.com/fluxisus/naspip-go/v3)
[![License](https://img.shields.io/github/license/fluxisus/naspip-go)](LICENSE)

Golang library implementing the Network-Agnostic Secure Payment Instructions Protocol ([NASPIP](https://github.com/fluxisus/naspip)). This library enables the creation and validation of standardized payment instructions for cryptocurrencies and other digital assets.

## Overview

NASPIP proposes a secure and standardized format for sharing payment instructions.

It uses [**PASETO V4 Token**](https://paseto.io/) technology with asymmetric signature (`private/public key pair`) as a standard to validate the information, and establishes the data structure for payment instructions.

This protocol enables secure interoperability between payment/collection platforms and facilitates the generation of a user-friendly UI/UX for the adoption of cryptocurrency payment methods.


## Installation

```bash
go get github.com/fluxisus/naspip-go/v3
```

## Usage Examples

### Create a Payment Instruction

```go
package main

import (
	"fmt"
	"time"

	"github.com/fluxisus/naspip-go/v3/paseto"
	"github.com/fluxisus/naspip-go/v3/protocol"
)

func main() {
	// Create a PASETO handler
	pasetoHandler := paseto.PasetoV4Handler()

	// Generate a key pair (for example purposes)
	keys, err := paseto.GenerateKey("public", "paserk")
	if err != nil {
		panic(err)
	}

	// Create a payment instructions builder
	builder := protocol.PaymentInstructionsBuilder{
		PasetoHandler: pasetoHandler,
	}

	// Create a payment instruction
	paymentInstruction := protocol.InstructionPayload{
		Payment: protocol.PaymentInstruction{
			Id:            "payment123",
			Address:       "TRjE1H8dxypKM1NZRdysbs9wo7huR4bdNz",
			UniqueAssetId: "ntrc20_tTR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
			IsOpen:        false,
			Amount:        "10.52",
			ExpiresAt:     time.Now().Add(1 * time.Hour).UnixMilli(),
		},
		Order: protocol.InstructionOrder{
			Total:       "10.52",
			CoinCode:    "USD",
			Description: "Payment for XYZ service",
			Merchant: protocol.InstructionMerchant{
				Name: "My Store",
			},
		},
	}

	// Options for token creation
	options := protocol.QrCriptoCreateOptions{
		SignOptions: paseto.PasetoSignOptions{
			KeyId: "my-key-id",
            Issuer: "my-company-name",
			ExpiresIn: "3h",
			Assertion: []byte(keys["publicKey"]),
		},
		KeyIssuer:     "my-key-issuer",
		KeyExpiration: time.Now().Add(10 * 365 * 24 * time.Hour).Format(time.RFC3339), // 10 years
	}

	// Create the signed payment instruction
	token, err := builder.CreatePaymentInstruction(paymentInstruction, keys["secretKey"], options)
	if err != nil {
		panic(err)
	}

	// Print the NASPIP token
	fmt.Printf("QR Token: %s\n", token)
}
```

### Read and Verify a Payment Instruction

```go
package main

import (
	"fmt"

	"github.com/fluxisus/naspip-go/v3/paseto"
	"github.com/fluxisus/naspip-go/v3/protocol"
)

func main() {
	// NASPIP token (obtained from a QR or link)
	naspipToken := "naspip;my-key-issuer;my-key-id;v4.public.eyJkYXRhIjp7..." // Token truncated for brevity

	// Issuer's public key
	publicKey := "issuer-public-key" // Could be paserk format

	// Create a PASETO handler
	pasetoHandler := paseto.PasetoV4Handler()

	// Create a payment instructions builder
	builder := protocol.PaymentInstructionsBuilder{
		PasetoHandler: pasetoHandler,
	}

	// Reading options
	options := protocol.QrCriptoReadOptions{
		KeyId:         "my-key-id",
		KeyIssuer:     "my-key-issuer",
	}

	// Read and verify the token
	result, err := builder.Read(naspipToken, publicKey, options)
	if err != nil {
		panic(err)
	}

	// Process the result
	fmt.Printf("Verified payment instruction: %+v\n", result)
}
```

### Create a Payment Link

```go
package main

import (
	"fmt"
	"time"

	"github.com/fluxisus/naspip-go/v3/paseto"
	"github.com/fluxisus/naspip-go/v3/protocol"
)

func main() {
	// Create a PASETO handler
	pasetoHandler := paseto.PasetoV4Handler()

	// Generate a key pair (for example purposes)
	keys, err := paseto.GenerateKey("public", "paserk")
	if err != nil {
		panic(err)
	}

	// Create a payment instructions builder
	builder := protocol.PaymentInstructionsBuilder{
		PasetoHandler: pasetoHandler,
	}

	// Create a URL payload
	urlPayload := protocol.UrlPayload{
		Url:            "https://mystore.com/payments/123",
		PaymentOptions: []string{"narbitrum_t0xaf88d065e77c8cC2239327C5EDb3A432268e5831", "navalanche_t0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7"},
		Order: protocol.InstructionOrder{
			Total:       "100",
			CoinCode:    "USD",
			Description: "Purchase from My Store",
		},
	}

	// Options for token creation
	options := protocol.QrCriptoCreateOptions{
		SignOptions: paseto.PasetoSignOptions{
			KeyId: "key1",
            Assertion: []byte(keys["publicKey"]),
		},
		KeyIssuer:     "mycompany",
		KeyExpiration: time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339), // 1 year
	}

	// Create the URL token
	token, err := builder.CreateUrlPayload(urlPayload, keys["secretKey"], options)
	if err != nil {
		panic(err)
	}

	// Print the NASPIP token
	fmt.Printf("QR Token: %s\n", token)
}
```

## NASPIP Protocol Implementation

### Key Components

NASPIP is built on the following technologies:

1. **PASETO v4**: Platform-Agnostic Security Tokens for the signing and verification of tokens.
2. **Protocol Buffers**: For efficient data serialization.
3. **Asymmetric Cryptography**: Public/private key pairs to ensure authenticity and integrity.

### NASPIP Token Structure

A NASPIP token has the format:

```
naspip;[key-issuer];[key-id];[paseto-token]
```

Where:
- `naspip`: Fixed prefix that identifies the protocol
- `[key-issuer]`: Identifies who issued the key
- `[key-id]`: Unique identifier of the key used
- `[paseto-token]`: PASETO v4 token containing the signed data

### Payload Types

The protocol supports two main payload types:

1. **InstructionPayload**: Contains complete payment instructions
   - Payment information (address, amount, asset, etc.)
   - Optional order information (total, merchant, description, etc.)

2. **UrlPayload**: Contains a URL that directs to a service that will generate the instructions
   - Destination URL
   - Available payment options
   - Optional order information

### Security

- **Asymmetric Signatures**: Ensures that only the private key holder can generate valid tokens
- **Date Validation**: Tokens have expiration dates to limit their validity
- **Key Identifiers**: Allow for key rotation and identifiers

### Protocol Advantages

1. **Standardization**: Single format for sharing payment instructions
2. **Security**: Cryptographic verification of instruction authenticity
3. **Flexibility**: Supports various asset types and variable amounts
4. **Interoperability**: Facilitates communication between different platforms and wallets
5. **Enhanced User Experience**: Enables the creation of user-friendly interfaces for cryptocurrency payments/transfers

## Features

* **Secure:** NASPIP implements an asymmetric encryption scheme, so that the payer can verify/validate the information generated by the collector.
* **Agnostic:** Can be used for any network and currency/token.
* **Interoperable:** Anyone can implement the protocol for reading and writing.
* **Easy to implement:** The implementation to read/write NASPIP Tokens is completely independent of who wants to use it.
* **Flexible:** Supports typical open/closed amount payment flows and dynamic/static payment data.

## Protocol Buffers 

> **Important Note**: Installing Protocol Buffers is **NOT required** to use this library or to contribute to most aspects of it. The following instructions are only necessary if you need to modify the Protocol Buffer definitions themselves, which is generally only needed for internal library development.

This library uses Protocol Buffers for efficient data serialization internally. The compiled Go code is already included in the repository, so you don't need to compile the `.proto` files yourself unless you're making changes to the data structures.

### Installation (Only for Protocol Buffer Development)

1. Install the protocol buffer compiler (protoc):

```bash
# Ubuntu/Debian
sudo apt install -y protobuf-compiler

# MacOS
brew install protobuf

# Verify installation
protoc --version
```

2. Install the Go protocol buffers plugin:

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
```

3. Add the Go bin directory to your PATH:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

### Usage (Only for Protocol Buffer Development)

1. Protocol buffer definitions are in `encoding/protobuf/model.proto`

2. To compile the protocol buffer definitions:

```bash
# From the project root
protoc --go_out=. encoding/protobuf/model.proto
```

3. The generated code will be placed in the same directory as the .proto file

### Development (Only for Protocol Buffer Development)

When modifying protocol buffer definitions:
1. Edit `encoding/protobuf/model.proto`
2. Recompile using the protoc command above
3. The generated Go code will be updated automatically

## Contributing

We welcome contributions to the NASPIP Go implementation! Here's how you can help:

### Reporting Issues

- Use the GitHub issue tracker to report bugs
- Describe what you expected to happen and what actually happened
- Include Go version, OS, and steps to reproduce the issue

### Pull Requests

1. Fork the repository
2. Create a new branch: `git checkout -b feature/your-feature-name`
3. Make your changes
4. Run tests and ensure they pass
5. Push to your fork: `git push origin feature/your-feature-name`
6. Submit a pull request

### Development Guidelines

- Follow Go best practices and style conventions
- Write Go tests for new code
- Document new methods and types
- Keep the API backward compatible when possible
- Run `go fmt` and `go vet` before committing

### Code of Conduct

- Be respectful in your interactions
- Focus on what is best for the community
- Welcome newcomers and encourage new contributors

## License

This project is licensed under the terms of the MIT license. See the [LICENSE](LICENSE) file for more details.