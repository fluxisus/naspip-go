// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.5
// 	protoc        v3.12.4
// source: encoding/protobuf/model.proto

package protobuf

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type PaymentInstruction struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Id            string                 `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Address       string                 `protobuf:"bytes,2,opt,name=address,proto3" json:"address,omitempty"`
	AddressTag    string                 `protobuf:"bytes,3,opt,name=address_tag,proto3" json:"address_tag,omitempty"`
	UniqueAssetId string                 `protobuf:"bytes,4,opt,name=unique_asset_id,proto3" json:"unique_asset_id,omitempty"`
	IsOpen        bool                   `protobuf:"varint,5,opt,name=is_open,proto3" json:"is_open,omitempty"`
	Amount        string                 `protobuf:"bytes,6,opt,name=amount,proto3" json:"amount,omitempty"`
	MinAmount     string                 `protobuf:"bytes,7,opt,name=min_amount,proto3" json:"min_amount,omitempty"`
	MaxAmount     string                 `protobuf:"bytes,8,opt,name=max_amount,proto3" json:"max_amount,omitempty"`
	ExpiresAt     int64                  `protobuf:"varint,9,opt,name=expires_at,proto3" json:"expires_at,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *PaymentInstruction) Reset() {
	*x = PaymentInstruction{}
	mi := &file_encoding_protobuf_model_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PaymentInstruction) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PaymentInstruction) ProtoMessage() {}

func (x *PaymentInstruction) ProtoReflect() protoreflect.Message {
	mi := &file_encoding_protobuf_model_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PaymentInstruction.ProtoReflect.Descriptor instead.
func (*PaymentInstruction) Descriptor() ([]byte, []int) {
	return file_encoding_protobuf_model_proto_rawDescGZIP(), []int{0}
}

func (x *PaymentInstruction) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *PaymentInstruction) GetAddress() string {
	if x != nil {
		return x.Address
	}
	return ""
}

func (x *PaymentInstruction) GetAddressTag() string {
	if x != nil {
		return x.AddressTag
	}
	return ""
}

func (x *PaymentInstruction) GetUniqueAssetId() string {
	if x != nil {
		return x.UniqueAssetId
	}
	return ""
}

func (x *PaymentInstruction) GetIsOpen() bool {
	if x != nil {
		return x.IsOpen
	}
	return false
}

func (x *PaymentInstruction) GetAmount() string {
	if x != nil {
		return x.Amount
	}
	return ""
}

func (x *PaymentInstruction) GetMinAmount() string {
	if x != nil {
		return x.MinAmount
	}
	return ""
}

func (x *PaymentInstruction) GetMaxAmount() string {
	if x != nil {
		return x.MaxAmount
	}
	return ""
}

func (x *PaymentInstruction) GetExpiresAt() int64 {
	if x != nil {
		return x.ExpiresAt
	}
	return 0
}

type InstructionMerchant struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Name          string                 `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Description   string                 `protobuf:"bytes,2,opt,name=description,proto3" json:"description,omitempty"`
	TaxId         string                 `protobuf:"bytes,3,opt,name=tax_id,proto3" json:"tax_id,omitempty"`
	Image         string                 `protobuf:"bytes,4,opt,name=image,proto3" json:"image,omitempty"`
	Mcc           string                 `protobuf:"bytes,5,opt,name=mcc,proto3" json:"mcc,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *InstructionMerchant) Reset() {
	*x = InstructionMerchant{}
	mi := &file_encoding_protobuf_model_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *InstructionMerchant) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InstructionMerchant) ProtoMessage() {}

func (x *InstructionMerchant) ProtoReflect() protoreflect.Message {
	mi := &file_encoding_protobuf_model_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InstructionMerchant.ProtoReflect.Descriptor instead.
func (*InstructionMerchant) Descriptor() ([]byte, []int) {
	return file_encoding_protobuf_model_proto_rawDescGZIP(), []int{1}
}

func (x *InstructionMerchant) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *InstructionMerchant) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *InstructionMerchant) GetTaxId() string {
	if x != nil {
		return x.TaxId
	}
	return ""
}

func (x *InstructionMerchant) GetImage() string {
	if x != nil {
		return x.Image
	}
	return ""
}

func (x *InstructionMerchant) GetMcc() string {
	if x != nil {
		return x.Mcc
	}
	return ""
}

type InstructionItem struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Description   string                 `protobuf:"bytes,1,opt,name=description,proto3" json:"description,omitempty"`
	Amount        string                 `protobuf:"bytes,2,opt,name=amount,proto3" json:"amount,omitempty"`
	CoinCode      string                 `protobuf:"bytes,3,opt,name=coin_code,proto3" json:"coin_code,omitempty"`
	Price         string                 `protobuf:"bytes,4,opt,name=price,json=unit_price,proto3" json:"price,omitempty"`
	Quantity      int32                  `protobuf:"varint,5,opt,name=quantity,proto3" json:"quantity,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *InstructionItem) Reset() {
	*x = InstructionItem{}
	mi := &file_encoding_protobuf_model_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *InstructionItem) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InstructionItem) ProtoMessage() {}

func (x *InstructionItem) ProtoReflect() protoreflect.Message {
	mi := &file_encoding_protobuf_model_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InstructionItem.ProtoReflect.Descriptor instead.
func (*InstructionItem) Descriptor() ([]byte, []int) {
	return file_encoding_protobuf_model_proto_rawDescGZIP(), []int{2}
}

func (x *InstructionItem) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *InstructionItem) GetAmount() string {
	if x != nil {
		return x.Amount
	}
	return ""
}

func (x *InstructionItem) GetCoinCode() string {
	if x != nil {
		return x.CoinCode
	}
	return ""
}

func (x *InstructionItem) GetPrice() string {
	if x != nil {
		return x.Price
	}
	return ""
}

func (x *InstructionItem) GetQuantity() int32 {
	if x != nil {
		return x.Quantity
	}
	return 0
}

type InstructionOrder struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Total         string                 `protobuf:"bytes,1,opt,name=total,proto3" json:"total,omitempty"`
	CoinCode      string                 `protobuf:"bytes,2,opt,name=coin_code,proto3" json:"coin_code,omitempty"`
	Description   string                 `protobuf:"bytes,3,opt,name=description,proto3" json:"description,omitempty"`
	Merchant      *InstructionMerchant   `protobuf:"bytes,4,opt,name=merchant,proto3" json:"merchant,omitempty"`
	Items         []*InstructionItem     `protobuf:"bytes,5,rep,name=items,proto3" json:"items,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *InstructionOrder) Reset() {
	*x = InstructionOrder{}
	mi := &file_encoding_protobuf_model_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *InstructionOrder) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InstructionOrder) ProtoMessage() {}

func (x *InstructionOrder) ProtoReflect() protoreflect.Message {
	mi := &file_encoding_protobuf_model_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InstructionOrder.ProtoReflect.Descriptor instead.
func (*InstructionOrder) Descriptor() ([]byte, []int) {
	return file_encoding_protobuf_model_proto_rawDescGZIP(), []int{3}
}

func (x *InstructionOrder) GetTotal() string {
	if x != nil {
		return x.Total
	}
	return ""
}

func (x *InstructionOrder) GetCoinCode() string {
	if x != nil {
		return x.CoinCode
	}
	return ""
}

func (x *InstructionOrder) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *InstructionOrder) GetMerchant() *InstructionMerchant {
	if x != nil {
		return x.Merchant
	}
	return nil
}

func (x *InstructionOrder) GetItems() []*InstructionItem {
	if x != nil {
		return x.Items
	}
	return nil
}

type InstructionPayload struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Payment       *PaymentInstruction    `protobuf:"bytes,1,opt,name=payment,proto3" json:"payment,omitempty"`
	Order         *InstructionOrder      `protobuf:"bytes,2,opt,name=order,proto3" json:"order,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *InstructionPayload) Reset() {
	*x = InstructionPayload{}
	mi := &file_encoding_protobuf_model_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *InstructionPayload) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InstructionPayload) ProtoMessage() {}

func (x *InstructionPayload) ProtoReflect() protoreflect.Message {
	mi := &file_encoding_protobuf_model_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InstructionPayload.ProtoReflect.Descriptor instead.
func (*InstructionPayload) Descriptor() ([]byte, []int) {
	return file_encoding_protobuf_model_proto_rawDescGZIP(), []int{4}
}

func (x *InstructionPayload) GetPayment() *PaymentInstruction {
	if x != nil {
		return x.Payment
	}
	return nil
}

func (x *InstructionPayload) GetOrder() *InstructionOrder {
	if x != nil {
		return x.Order
	}
	return nil
}

type UrlPayload struct {
	state          protoimpl.MessageState `protogen:"open.v1"`
	Url            string                 `protobuf:"bytes,1,opt,name=url,proto3" json:"url,omitempty"`
	PaymentOptions []string               `protobuf:"bytes,2,rep,name=payment_options,proto3" json:"payment_options,omitempty"`
	Order          *InstructionOrder      `protobuf:"bytes,3,opt,name=order,proto3" json:"order,omitempty"`
	unknownFields  protoimpl.UnknownFields
	sizeCache      protoimpl.SizeCache
}

func (x *UrlPayload) Reset() {
	*x = UrlPayload{}
	mi := &file_encoding_protobuf_model_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *UrlPayload) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UrlPayload) ProtoMessage() {}

func (x *UrlPayload) ProtoReflect() protoreflect.Message {
	mi := &file_encoding_protobuf_model_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UrlPayload.ProtoReflect.Descriptor instead.
func (*UrlPayload) Descriptor() ([]byte, []int) {
	return file_encoding_protobuf_model_proto_rawDescGZIP(), []int{5}
}

func (x *UrlPayload) GetUrl() string {
	if x != nil {
		return x.Url
	}
	return ""
}

func (x *UrlPayload) GetPaymentOptions() []string {
	if x != nil {
		return x.PaymentOptions
	}
	return nil
}

func (x *UrlPayload) GetOrder() *InstructionOrder {
	if x != nil {
		return x.Order
	}
	return nil
}

type PasetoTokenData struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	Iss   string                 `protobuf:"bytes,1,opt,name=iss,proto3" json:"iss,omitempty"`
	Sub   string                 `protobuf:"bytes,2,opt,name=sub,proto3" json:"sub,omitempty"`
	Aud   string                 `protobuf:"bytes,3,opt,name=aud,proto3" json:"aud,omitempty"`
	Exp   string                 `protobuf:"bytes,4,opt,name=exp,proto3" json:"exp,omitempty"`
	Nbf   string                 `protobuf:"bytes,5,opt,name=nbf,proto3" json:"nbf,omitempty"`
	Iat   string                 `protobuf:"bytes,6,opt,name=iat,proto3" json:"iat,omitempty"`
	Jti   string                 `protobuf:"bytes,7,opt,name=jti,proto3" json:"jti,omitempty"`
	Kid   string                 `protobuf:"bytes,8,opt,name=kid,proto3" json:"kid,omitempty"`
	Kep   string                 `protobuf:"bytes,9,opt,name=kep,proto3" json:"kep,omitempty"`
	Kis   string                 `protobuf:"bytes,10,opt,name=kis,proto3" json:"kis,omitempty"`
	// Types that are valid to be assigned to Data:
	//
	//	*PasetoTokenData_InstructionPayload
	//	*PasetoTokenData_UrlPayload
	Data          isPasetoTokenData_Data `protobuf_oneof:"data"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *PasetoTokenData) Reset() {
	*x = PasetoTokenData{}
	mi := &file_encoding_protobuf_model_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PasetoTokenData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PasetoTokenData) ProtoMessage() {}

func (x *PasetoTokenData) ProtoReflect() protoreflect.Message {
	mi := &file_encoding_protobuf_model_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PasetoTokenData.ProtoReflect.Descriptor instead.
func (*PasetoTokenData) Descriptor() ([]byte, []int) {
	return file_encoding_protobuf_model_proto_rawDescGZIP(), []int{6}
}

func (x *PasetoTokenData) GetIss() string {
	if x != nil {
		return x.Iss
	}
	return ""
}

func (x *PasetoTokenData) GetSub() string {
	if x != nil {
		return x.Sub
	}
	return ""
}

func (x *PasetoTokenData) GetAud() string {
	if x != nil {
		return x.Aud
	}
	return ""
}

func (x *PasetoTokenData) GetExp() string {
	if x != nil {
		return x.Exp
	}
	return ""
}

func (x *PasetoTokenData) GetNbf() string {
	if x != nil {
		return x.Nbf
	}
	return ""
}

func (x *PasetoTokenData) GetIat() string {
	if x != nil {
		return x.Iat
	}
	return ""
}

func (x *PasetoTokenData) GetJti() string {
	if x != nil {
		return x.Jti
	}
	return ""
}

func (x *PasetoTokenData) GetKid() string {
	if x != nil {
		return x.Kid
	}
	return ""
}

func (x *PasetoTokenData) GetKep() string {
	if x != nil {
		return x.Kep
	}
	return ""
}

func (x *PasetoTokenData) GetKis() string {
	if x != nil {
		return x.Kis
	}
	return ""
}

func (x *PasetoTokenData) GetData() isPasetoTokenData_Data {
	if x != nil {
		return x.Data
	}
	return nil
}

func (x *PasetoTokenData) GetInstructionPayload() *InstructionPayload {
	if x != nil {
		if x, ok := x.Data.(*PasetoTokenData_InstructionPayload); ok {
			return x.InstructionPayload
		}
	}
	return nil
}

func (x *PasetoTokenData) GetUrlPayload() *UrlPayload {
	if x != nil {
		if x, ok := x.Data.(*PasetoTokenData_UrlPayload); ok {
			return x.UrlPayload
		}
	}
	return nil
}

type isPasetoTokenData_Data interface {
	isPasetoTokenData_Data()
}

type PasetoTokenData_InstructionPayload struct {
	InstructionPayload *InstructionPayload `protobuf:"bytes,11,opt,name=instruction_payload,json=data,proto3,oneof"`
}

type PasetoTokenData_UrlPayload struct {
	UrlPayload *UrlPayload `protobuf:"bytes,12,opt,name=url_payload,json=data,proto3,oneof"`
}

func (*PasetoTokenData_InstructionPayload) isPasetoTokenData_Data() {}

func (*PasetoTokenData_UrlPayload) isPasetoTokenData_Data() {}

var File_encoding_protobuf_model_proto protoreflect.FileDescriptor

var file_encoding_protobuf_model_proto_rawDesc = string([]byte{
	0x0a, 0x1d, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2f, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x08, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x22, 0x9c, 0x02, 0x0a, 0x12, 0x50, 0x61,
	0x79, 0x6d, 0x65, 0x6e, 0x74, 0x49, 0x6e, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64,
	0x12, 0x18, 0x0a, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x20, 0x0a, 0x0b, 0x61, 0x64,
	0x64, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x74, 0x61, 0x67, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x0b, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x74, 0x61, 0x67, 0x12, 0x28, 0x0a, 0x0f,
	0x75, 0x6e, 0x69, 0x71, 0x75, 0x65, 0x5f, 0x61, 0x73, 0x73, 0x65, 0x74, 0x5f, 0x69, 0x64, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0f, 0x75, 0x6e, 0x69, 0x71, 0x75, 0x65, 0x5f, 0x61, 0x73,
	0x73, 0x65, 0x74, 0x5f, 0x69, 0x64, 0x12, 0x18, 0x0a, 0x07, 0x69, 0x73, 0x5f, 0x6f, 0x70, 0x65,
	0x6e, 0x18, 0x05, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x69, 0x73, 0x5f, 0x6f, 0x70, 0x65, 0x6e,
	0x12, 0x16, 0x0a, 0x06, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x06, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x1e, 0x0a, 0x0a, 0x6d, 0x69, 0x6e, 0x5f,
	0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x6d, 0x69,
	0x6e, 0x5f, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x1e, 0x0a, 0x0a, 0x6d, 0x61, 0x78, 0x5f,
	0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x6d, 0x61,
	0x78, 0x5f, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x1e, 0x0a, 0x0a, 0x65, 0x78, 0x70, 0x69,
	0x72, 0x65, 0x73, 0x5f, 0x61, 0x74, 0x18, 0x09, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0a, 0x65, 0x78,
	0x70, 0x69, 0x72, 0x65, 0x73, 0x5f, 0x61, 0x74, 0x22, 0x8b, 0x01, 0x0a, 0x13, 0x49, 0x6e, 0x73,
	0x74, 0x72, 0x75, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x4d, 0x65, 0x72, 0x63, 0x68, 0x61, 0x6e, 0x74,
	0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04,
	0x6e, 0x61, 0x6d, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74,
	0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72,
	0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x16, 0x0a, 0x06, 0x74, 0x61, 0x78, 0x5f, 0x69, 0x64,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x74, 0x61, 0x78, 0x5f, 0x69, 0x64, 0x12, 0x14,
	0x0a, 0x05, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x69,
	0x6d, 0x61, 0x67, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x6d, 0x63, 0x63, 0x18, 0x05, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x03, 0x6d, 0x63, 0x63, 0x22, 0xa0, 0x01, 0x0a, 0x0f, 0x49, 0x6e, 0x73, 0x74, 0x72,
	0x75, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x74, 0x65, 0x6d, 0x12, 0x20, 0x0a, 0x0b, 0x64, 0x65,
	0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x16, 0x0a, 0x06,
	0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x61, 0x6d,
	0x6f, 0x75, 0x6e, 0x74, 0x12, 0x1c, 0x0a, 0x09, 0x63, 0x6f, 0x69, 0x6e, 0x5f, 0x63, 0x6f, 0x64,
	0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x63, 0x6f, 0x69, 0x6e, 0x5f, 0x63, 0x6f,
	0x64, 0x65, 0x12, 0x19, 0x0a, 0x05, 0x70, 0x72, 0x69, 0x63, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0a, 0x75, 0x6e, 0x69, 0x74, 0x5f, 0x70, 0x72, 0x69, 0x63, 0x65, 0x12, 0x1a, 0x0a,
	0x08, 0x71, 0x75, 0x61, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x18, 0x05, 0x20, 0x01, 0x28, 0x05, 0x52,
	0x08, 0x71, 0x75, 0x61, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x22, 0xd4, 0x01, 0x0a, 0x10, 0x49, 0x6e,
	0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x4f, 0x72, 0x64, 0x65, 0x72, 0x12, 0x14,
	0x0a, 0x05, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x74,
	0x6f, 0x74, 0x61, 0x6c, 0x12, 0x1c, 0x0a, 0x09, 0x63, 0x6f, 0x69, 0x6e, 0x5f, 0x63, 0x6f, 0x64,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x63, 0x6f, 0x69, 0x6e, 0x5f, 0x63, 0x6f,
	0x64, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f,
	0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x12, 0x39, 0x0a, 0x08, 0x6d, 0x65, 0x72, 0x63, 0x68, 0x61, 0x6e, 0x74,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1d, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x49, 0x6e, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x4d, 0x65, 0x72,
	0x63, 0x68, 0x61, 0x6e, 0x74, 0x52, 0x08, 0x6d, 0x65, 0x72, 0x63, 0x68, 0x61, 0x6e, 0x74, 0x12,
	0x2f, 0x0a, 0x05, 0x69, 0x74, 0x65, 0x6d, 0x73, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x19,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x49, 0x6e, 0x73, 0x74, 0x72, 0x75,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x74, 0x65, 0x6d, 0x52, 0x05, 0x69, 0x74, 0x65, 0x6d, 0x73,
	0x22, 0x7e, 0x0a, 0x12, 0x49, 0x6e, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x50,
	0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x12, 0x36, 0x0a, 0x07, 0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e,
	0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x50, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x49, 0x6e, 0x73, 0x74, 0x72, 0x75,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x07, 0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x12, 0x30,
	0x0a, 0x05, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x49, 0x6e, 0x73, 0x74, 0x72, 0x75, 0x63,
	0x74, 0x69, 0x6f, 0x6e, 0x4f, 0x72, 0x64, 0x65, 0x72, 0x52, 0x05, 0x6f, 0x72, 0x64, 0x65, 0x72,
	0x22, 0x7a, 0x0a, 0x0a, 0x55, 0x72, 0x6c, 0x50, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x12, 0x10,
	0x0a, 0x03, 0x75, 0x72, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x75, 0x72, 0x6c,
	0x12, 0x28, 0x0a, 0x0f, 0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x5f, 0x6f, 0x70, 0x74, 0x69,
	0x6f, 0x6e, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0f, 0x70, 0x61, 0x79, 0x6d, 0x65,
	0x6e, 0x74, 0x5f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x30, 0x0a, 0x05, 0x6f, 0x72,
	0x64, 0x65, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2e, 0x49, 0x6e, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x4f, 0x72, 0x64, 0x65, 0x72, 0x52, 0x05, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x22, 0xc3, 0x02, 0x0a,
	0x0f, 0x50, 0x61, 0x73, 0x65, 0x74, 0x6f, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x44, 0x61, 0x74, 0x61,
	0x12, 0x10, 0x0a, 0x03, 0x69, 0x73, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x69,
	0x73, 0x73, 0x12, 0x10, 0x0a, 0x03, 0x73, 0x75, 0x62, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x03, 0x73, 0x75, 0x62, 0x12, 0x10, 0x0a, 0x03, 0x61, 0x75, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x03, 0x61, 0x75, 0x64, 0x12, 0x10, 0x0a, 0x03, 0x65, 0x78, 0x70, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x03, 0x65, 0x78, 0x70, 0x12, 0x10, 0x0a, 0x03, 0x6e, 0x62, 0x66, 0x18,
	0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6e, 0x62, 0x66, 0x12, 0x10, 0x0a, 0x03, 0x69, 0x61,
	0x74, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x69, 0x61, 0x74, 0x12, 0x10, 0x0a, 0x03,
	0x6a, 0x74, 0x69, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6a, 0x74, 0x69, 0x12, 0x10,
	0x0a, 0x03, 0x6b, 0x69, 0x64, 0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x69, 0x64,
	0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x70, 0x18, 0x09, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b,
	0x65, 0x70, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x69, 0x73, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x03, 0x6b, 0x69, 0x73, 0x12, 0x41, 0x0a, 0x13, 0x69, 0x6e, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74,
	0x69, 0x6f, 0x6e, 0x5f, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x18, 0x0b, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x1c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x49, 0x6e, 0x73,
	0x74, 0x72, 0x75, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x50, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x48,
	0x00, 0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x12, 0x31, 0x0a, 0x0b, 0x75, 0x72, 0x6c, 0x5f, 0x70,
	0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x55, 0x72, 0x6c, 0x50, 0x61, 0x79, 0x6c, 0x6f,
	0x61, 0x64, 0x48, 0x00, 0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x42, 0x06, 0x0a, 0x04, 0x64, 0x61,
	0x74, 0x61, 0x42, 0x13, 0x5a, 0x11, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x2f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
})

var (
	file_encoding_protobuf_model_proto_rawDescOnce sync.Once
	file_encoding_protobuf_model_proto_rawDescData []byte
)

func file_encoding_protobuf_model_proto_rawDescGZIP() []byte {
	file_encoding_protobuf_model_proto_rawDescOnce.Do(func() {
		file_encoding_protobuf_model_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_encoding_protobuf_model_proto_rawDesc), len(file_encoding_protobuf_model_proto_rawDesc)))
	})
	return file_encoding_protobuf_model_proto_rawDescData
}

var file_encoding_protobuf_model_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_encoding_protobuf_model_proto_goTypes = []any{
	(*PaymentInstruction)(nil),  // 0: protobuf.PaymentInstruction
	(*InstructionMerchant)(nil), // 1: protobuf.InstructionMerchant
	(*InstructionItem)(nil),     // 2: protobuf.InstructionItem
	(*InstructionOrder)(nil),    // 3: protobuf.InstructionOrder
	(*InstructionPayload)(nil),  // 4: protobuf.InstructionPayload
	(*UrlPayload)(nil),          // 5: protobuf.UrlPayload
	(*PasetoTokenData)(nil),     // 6: protobuf.PasetoTokenData
}
var file_encoding_protobuf_model_proto_depIdxs = []int32{
	1, // 0: protobuf.InstructionOrder.merchant:type_name -> protobuf.InstructionMerchant
	2, // 1: protobuf.InstructionOrder.items:type_name -> protobuf.InstructionItem
	0, // 2: protobuf.InstructionPayload.payment:type_name -> protobuf.PaymentInstruction
	3, // 3: protobuf.InstructionPayload.order:type_name -> protobuf.InstructionOrder
	3, // 4: protobuf.UrlPayload.order:type_name -> protobuf.InstructionOrder
	4, // 5: protobuf.PasetoTokenData.instruction_payload:type_name -> protobuf.InstructionPayload
	5, // 6: protobuf.PasetoTokenData.url_payload:type_name -> protobuf.UrlPayload
	7, // [7:7] is the sub-list for method output_type
	7, // [7:7] is the sub-list for method input_type
	7, // [7:7] is the sub-list for extension type_name
	7, // [7:7] is the sub-list for extension extendee
	0, // [0:7] is the sub-list for field type_name
}

func init() { file_encoding_protobuf_model_proto_init() }
func file_encoding_protobuf_model_proto_init() {
	if File_encoding_protobuf_model_proto != nil {
		return
	}
	file_encoding_protobuf_model_proto_msgTypes[6].OneofWrappers = []any{
		(*PasetoTokenData_InstructionPayload)(nil),
		(*PasetoTokenData_UrlPayload)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_encoding_protobuf_model_proto_rawDesc), len(file_encoding_protobuf_model_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_encoding_protobuf_model_proto_goTypes,
		DependencyIndexes: file_encoding_protobuf_model_proto_depIdxs,
		MessageInfos:      file_encoding_protobuf_model_proto_msgTypes,
	}.Build()
	File_encoding_protobuf_model_proto = out.File
	file_encoding_protobuf_model_proto_goTypes = nil
	file_encoding_protobuf_model_proto_depIdxs = nil
}
