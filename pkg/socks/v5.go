// Copyright 2025
// Licensed under the  Apache License

package socks

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

type SocksV5Negotiate struct {
	Version   byte
	NoMethods byte
	Methods   []byte
}

func (sn *SocksV5Negotiate) String() string {
	return ""
}

func (sn *SocksV5Negotiate) Marshal() ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

type SocksV5Connect struct {
	Version byte
	Command byte
	Rsv     byte
	Atyp    byte
	Address string
	Port    uint16
	Network string
}

func (sn *SocksV5Connect) String() string {
	return ""
}
func (sn *SocksV5Connect) Marshal() ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

type SocksV5Authenticate struct {
	Version  byte
	Username string
	Password string
}

func (sn *SocksV5Authenticate) String() string {
	return fmt.Sprintf("version=%v,username=%v", sn.Version, sn.Username)
}
func (sn *SocksV5Authenticate) Marshal() ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

type SocksV5Connection struct {
	conn net.Conn
	br   *bufio.Reader
}

func (sc *SocksV5Connection) ReadMessage(messageType SocksMessageType) (SocksMessage, error) {
	switch messageType {
	case MessageNegotiate:
		version, err := sc.br.ReadByte()
		if err != nil {
			return nil, err
		}
		nMethods, err := sc.br.ReadByte()
		if err != nil {
			return nil, err
		}
		methods := make([]byte, int(nMethods))
		if _, err := io.ReadFull(sc.br, methods); err != nil {
			return nil, err
		}
		return &SocksV5Negotiate{
			Version:   version,
			NoMethods: nMethods,
			Methods:   methods,
		}, nil

	case MessageRequest:
		version, err := sc.br.ReadByte()
		if err != nil { // Version
			return nil, err
		}
		command, err := sc.br.ReadByte()
		if err != nil { // Command
			return nil, err
		}
		rsv, err := sc.br.ReadByte()
		if err != nil { // RSV
			return nil, err
		}
		atyp, err := sc.br.ReadByte()
		if err != nil { //Address Type
			return nil, err
		}
		var addr string
		switch atyp {
		case ATYP_IPV4:
			ipv4 := make([]byte, 4)
			if _, err := io.ReadFull(sc.br, ipv4); err != nil {
				return nil, err
			}
			addr = net.IP(ipv4).String()
		case ATYP_IPV6:
			ipv6 := make([]byte, 16)
			if _, err := io.ReadFull(sc.br, ipv6); err != nil {
				return nil, err
			}
			addr = net.IP(ipv6).String()
		case ATYP_DOMAIN:
			dLen, err := sc.br.ReadByte()
			if err != nil {
				return nil, err
			}
			dns := make([]byte, dLen)
			if _, err := io.ReadFull(sc.br, dns); err != nil {
				return nil, err
			}

			ips, err := net.LookupIP(string(dns))
			if err != nil {
				return nil, err
			}
			if len(ips) > 0 {
				addr = ips[0].To4().String()
			} else {
				return nil, fmt.Errorf("dns: A record not found")
			}
		}

		port := make([]byte, 2)
		if _, err = sc.br.Read(port); err != nil {
			return nil, err
		}
		var portNum uint16
		if _, err := binary.Decode(port, binary.BigEndian,
			&portNum); err != nil {
			return nil, err
		}

		msg := &SocksV5Connect{
			Version: version,
			Command: command,
			Rsv:     rsv,
			Atyp:    atyp,
			Address: addr,
			Port:    portNum,
		}

		switch command {
		case CMD_CONNECT:
			msg.Network = "tcp"
		default:
			msg.Network = "udp"
		}
		return msg, nil

	case MessageUserPassAuth:
		version, err := sc.br.ReadByte()
		if err != nil { // Version
			return nil, err
		}
		uLen, err := sc.br.ReadByte()
		if err != nil { // Version
			return nil, err
		}
		username := make([]byte, int(uLen))
		if _, err = sc.br.Read(username); err != nil {
			return nil, err
		}
		pLen, err := sc.br.ReadByte()
		if err != nil { // Version
			return nil, err
		}
		password := make([]byte, int(pLen))
		if _, err = sc.br.Read(username); err != nil {
			return nil, err
		}

		return &SocksV5Authenticate{
			Version:  version,
			Username: string(username),
			Password: string(password),
		}, nil

	default:
		return nil, fmt.Errorf("invalid message type:%v", messageType)
	}
}

func (sc *SocksV5Connection) WriteMessage(messageType SocksMessageType, connectionArgs ...func(*ConnectionArgs)) (err error) {
	switch messageType {
	case MessageNoAuth:
		bw := bufio.NewWriter(sc.conn)
		if err := bw.WriteByte(SOCKS5_VERSION); err != nil {
			return err
		}
		if err := bw.WriteByte(AUTH_NO_AUTH); err != nil {
			return err
		}
		return bw.Flush()

	case MessageUserPassAuth:
		bw := bufio.NewWriter(sc.conn)
		if err := bw.WriteByte(SOCKS5_VERSION); err != nil {
			return err
		}
		if err := bw.WriteByte(AUTH_USERNAME_PASS); err != nil {
			return err
		}
		return bw.Flush()

	case MessageUserPassAuthSuccess:
		bw := bufio.NewWriter(sc.conn)
		if err := bw.WriteByte(SOCKS5_VERSION); err != nil {
			return err
		}
		if err := bw.WriteByte(USERPASS_SUCCESS); err != nil {
			return err
		}
		return bw.Flush()

	case MessageRequestSuccess:
		bw := bufio.NewWriter(sc.conn)
		if err := bw.WriteByte(SOCKS5_VERSION); err != nil {
			return err
		}
		if err := bw.WriteByte(REP_SUCCESS); err != nil {
			return err
		}
		if err := bw.WriteByte(RSV); err != nil {
			return err
		}
		args := new(ConnectionArgs)
		for _, argFunc := range connectionArgs {
			argFunc(args)
		}
		switch args.AddressType {
		case ATYP_IPV4:
			if err := bw.WriteByte(ATYP_IPV4); err != nil {
				return err
			}
			if _, err := bw.Write([]byte{0x00, 0x00, 0x00, 0x00}); err != nil { //IPv4
				return err
			}
		}
		if _, err := bw.Write([]byte{0x00, 0x00}); err != nil { //Port
			return err
		}
		return bw.Flush()

	case MessageNoMethods:
		bw := bufio.NewWriter(sc.conn)
		if err := bw.WriteByte(SOCKS5_VERSION); err != nil {
			return err
		}
		if err := bw.WriteByte(AUTH_NO_METHODS); err != nil {
			return err
		}
		return bw.Flush()

	default:
		return fmt.Errorf("invalid message type:%v", messageType)
	}
}

type ConnectionArgs struct {
	AddressType byte
}

func WithAddressType(aType byte) func(*ConnectionArgs) {
	return func(args *ConnectionArgs) {
		args.AddressType = aType
	}
}

func (sc *SocksV5Connection) UnWrap() net.Conn {
	return sc.conn
}

func (sc *SocksV5Connection) Close() error {
	return sc.conn.Close()
}
