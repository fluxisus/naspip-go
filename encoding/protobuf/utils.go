package protobuf

import (
	"encoding/json"
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func DecodeProto(payload []byte, data proto.Message) error {
	if err := proto.Unmarshal(payload, data); err != nil {
		return err
	}

	return nil
}

func EncodeProto(data proto.Message) ([]byte, error) {
	return proto.Marshal(data)
}

// ConvertGoToProto convierte cualquier estructura Go a su equivalente Protobuf
func ConvertGoToProto[T any, P interface{ proto.Message }](goStruct T, protoMsg P) error {
	// 1. Convertir la estructura Go a JSON
	jsonBytes, err := json.Marshal(goStruct)
	if err != nil {
		return fmt.Errorf("error al convertir a JSON: %v", err)
	}

	// 2. Crear un unmarshaler de JSON a Protobuf con opciones para manejar diferencias en nombres
	unmarshaler := protojson.UnmarshalOptions{
		DiscardUnknown: true, // Ignorar campos desconocidos
		AllowPartial:   true, // Permitir mensajes parciales
	}

	// 3. Convertir JSON a la estructura Protobuf
	if err := unmarshaler.Unmarshal(jsonBytes, protoMsg); err != nil {
		return fmt.Errorf("error al convertir JSON a Protobuf: %v", err)
	}

	return nil
}

// ConvertProtoToGo convierte cualquier estructura Protobuf a su equivalente Go
func ConvertProtoToGo[P proto.Message, T any](protoMsg P, goStruct *T) error {
	// 1. Convertir Protobuf a JSON
	marshaler := protojson.MarshalOptions{
		UseProtoNames:   false, // Usar nombres camelCase para JSON
		EmitUnpopulated: false, // Incluir campos por defecto
	}

	jsonBytes, err := marshaler.Marshal(protoMsg)
	if err != nil {
		return fmt.Errorf("error al convertir Protobuf a JSON: %v", err)
	}

	// 2. Convertir JSON a la estructura Go
	if err := json.Unmarshal(jsonBytes, goStruct); err != nil {
		return fmt.Errorf("error al convertir JSON a estructura Go: %v", err)
	}

	return nil
}
