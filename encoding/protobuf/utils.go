// Package protobuf provides Protocol Buffer utilities for the NASPIP protocol.
// It defines data structures for payment instructions and offers serialization/deserialization
// functionality between Protocol Buffers, JSON, and Go structs.
package protobuf

import (
	"encoding/json"
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// DecodeProto unmarshals binary Protocol Buffer data into a protobuf message.
// It decodes binary-encoded Protocol Buffer data back into the structured message.
//
// Parameters:
//   - payload: Binary Protocol Buffer encoded data
//   - data: Protocol Buffer message to unmarshal into
//
// Returns:
//   - An error if unmarshalling fails, nil on success
func DecodeProto(payload []byte, data proto.Message) error {
	if err := proto.Unmarshal(payload, data); err != nil {
		return err
	}

	return nil
}

// EncodeProto marshals a protobuf message into binary Protocol Buffer format.
// This binary format is space-efficient and suitable for serialization.
//
// Parameters:
//   - data: Protocol Buffer message to marshal
//
// Returns:
//   - The binary Protocol Buffer representation
//   - An error if marshalling fails
func EncodeProto(data proto.Message) ([]byte, error) {
	return proto.Marshal(data)
}

// ConvertGoToProto converts a Go struct to its equivalent Protocol Buffer message.
// It uses JSON as an intermediate format to handle conversion between different types.
//
// Type Parameters:
//   - T: Any Go struct type
//   - P: Any Protocol Buffer message type
//
// Parameters:
//   - goStruct: The source Go struct to convert
//   - protoMsg: The target Protocol Buffer message to populate
//
// Returns:
//   - An error if conversion fails, nil on success
func ConvertGoToProto[T any, P interface{ proto.Message }](goStruct T, protoMsg P) error {
	// 1. Convert Go struct to JSON
	jsonBytes, err := json.Marshal(goStruct)
	if err != nil {
		return fmt.Errorf("error converting to JSON: %v", err)
	}

	// 2. Create a JSON to Protocol Buffer unmarshaler with options to handle name differences
	unmarshaler := protojson.UnmarshalOptions{
		DiscardUnknown: true, // Ignore unknown fields
		AllowPartial:   true, // Allow partial messages
	}

	// 3. Convert JSON to Protocol Buffer structure
	if err := unmarshaler.Unmarshal(jsonBytes, protoMsg); err != nil {
		return fmt.Errorf("error converting JSON to Protocol Buffer: %v", err)
	}

	return nil
}

// ConvertProtoToGo converts a Protocol Buffer message to its equivalent Go struct.
// It uses JSON as an intermediate format to handle conversion between different types.
//
// Type Parameters:
//   - P: Any Protocol Buffer message type
//   - T: Any Go struct type
//
// Parameters:
//   - protoMsg: The source Protocol Buffer message to convert
//   - goStruct: Pointer to the target Go struct to populate
//
// Returns:
//   - An error if conversion fails, nil on success
func ConvertProtoToGo[P proto.Message, T any](protoMsg P, goStruct *T) error {
	// 1. Convert Protocol Buffer to JSON
	marshaler := protojson.MarshalOptions{
		UseProtoNames:   false, // Use camelCase names for JSON
		EmitUnpopulated: false, // Include default fields
	}

	jsonBytes, err := marshaler.Marshal(protoMsg)
	if err != nil {
		return fmt.Errorf("error converting Protocol Buffer to JSON: %v", err)
	}

	// 2. Convert JSON to Go struct
	if err := json.Unmarshal(jsonBytes, goStruct); err != nil {
		return fmt.Errorf("error converting JSON to Go struct: %v", err)
	}

	return nil
}
