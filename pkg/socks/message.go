// Copyright 2025
// Licensed under the  Apache License

package socks

type SocksMessageType int

const (
	MessageNegotiate SocksMessageType = iota
	MessageRequest
	MessageNoAuth
	MessageUserPassAuth
	MessageUserPassAuthSuccess
	MessageNoMethods
	MessageRequestSuccess
)
