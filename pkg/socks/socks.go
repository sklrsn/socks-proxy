// Copyright 2025
// Licensed under the  Apache License

package socks

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"

	"github.com/sklrsn/socks-proxy/pkg/logger"
)

type SocksConnection interface {
	ReadMessage(SocksMessageType) (SocksMessage, error)
	WriteMessage(SocksMessageType, ...func(*ConnectionArgs)) error
	UnWrap() net.Conn
	Close() error
}

type SocksMessage interface {
	String() string
	Marshal() ([]byte, error)
}

type SocksServer struct {
	port   int
	protos []byte
}

func NewSocksServer(params ...func(*SocksServer)) *SocksServer {
	ss := &SocksServer{
		port:   1080,
		protos: make([]byte, 0),
	}

	for _, param := range params {
		param(ss)
	}

	return ss
}

func (ss *SocksServer) Start() error {
	lr, err := net.Listen("tcp", fmt.Sprintf(":%v", ss.port))
	if err != nil {
		logger.Errorf("SOCKS server listener error:%v", err)
		return err
	}
	defer lr.Close()

	for {
		conn, err := lr.Accept()
		if err != nil {
			logger.Errorf("SOCKS server listener error:%v", err)
			continue
		}

		logger.Infof("SOCKs connection from :%v", conn.RemoteAddr())

		go func() {
			defer conn.Close()
			br := bufio.NewReader(conn)
			ver, err := br.ReadByte()
			if err != nil {
				logger.Errorf("SOCKS connection error:%v", err)
				return
			}
			if err := br.UnreadByte(); err != nil {
				logger.Errorf("SOCKS connection error:%v", err)
				return
			}
			var sockConn SocksConnection
			switch ver {
			case SOCKS5_VERSION:
				sockConn = &SocksV5Connection{
					conn: conn,
					br:   br,
				}
			default:
				logger.Errorf("SOCKS connection error:%v", err)
			}
			if err := ss.Serve(sockConn); err != nil {
				logger.Errorf("SOCKS connection error:%v", err)
				return
			}
		}()
	}
}

func (ss *SocksServer) Serve(srcConn SocksConnection) error {
	negoMessage, err := srcConn.ReadMessage(MessageNegotiate)
	if err != nil {
		logger.Errorf("SOCKS negotiation error:%v", err)
		return err
	}
	switch msg := negoMessage.(type) {
	case *SocksV5Negotiate:
		switch msg.Version {
		case SOCKS5_VERSION:
			switch {
			case slices.Contains(msg.Methods, AUTH_USERNAME_PASS):
				if err := srcConn.WriteMessage(MessageUserPassAuth); err != nil {
					logger.Errorf("SOCKS negotiation error:%v", err)
					return err
				}
				msg, err := srcConn.ReadMessage(MessageUserPassAuth)
				if err != nil {
					logger.Errorf("SOCKS negotiation error:%v", err)
					return err
				}
				if err := srcConn.WriteMessage(MessageUserPassAuthSuccess); err != nil {
					logger.Errorf("SOCKS negotiation error:%v", err)
					return err
				}
				logger.Infof("SOCKS negotiation:%v", msg.String())
			case slices.Contains(msg.Methods, AUTH_NO_AUTH):
				if err := srcConn.WriteMessage(MessageNoAuth); err != nil {
					logger.Errorf("SOCKS negotiation error:%v", err)
					return err
				}
			default:
				if err := srcConn.WriteMessage(MessageNoMethods); err != nil {
					logger.Errorf("SOCKS negotiation error:%v", err)
					return err
				}
			}
		}
	}

	reqMessage, err := srcConn.ReadMessage(MessageRequest)
	if err != nil {
		logger.Errorf("SOCKS connection error:%v", err)
		return err
	}
	switch msg := reqMessage.(type) {
	case *SocksV5Connect:
		switch msg.Version {
		case SOCKS5_VERSION:
			if err := srcConn.WriteMessage(MessageRequestSuccess,
				WithAddressType(msg.Atyp)); err != nil {
				logger.Errorf("SOCKS connection error:%v", err)
				return err
			}

			logger.Infof("SOCKS connection to the target %v:%v", msg.Address, msg.Port)

			var targetConn net.Conn
			targetConn, err := net.Dial(msg.Network, fmt.Sprintf("%v:%v",
				msg.Address, msg.Port))
			if err != nil {
				return err
			}

			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				io.Copy(srcConn.UnWrap(), targetConn)
			}()
			go func() {
				defer wg.Done()
				io.Copy(targetConn, srcConn.UnWrap())
			}()
			wg.Wait()

			_ = srcConn.Close()
			_ = targetConn.Close()
			return nil
		}
	}

	return fmt.Errorf("SOCKS connection error")
}

func WithPort(port int) func(ss *SocksServer) {
	return func(ss *SocksServer) {
		ss.port = port
	}
}

func WithProto(proto byte) func(ss *SocksServer) {
	return func(ss *SocksServer) {
		ss.protos = append(ss.protos, proto)
	}
}
