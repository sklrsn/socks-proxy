package main

import (
	"log"

	"github.com/sklrsn/socks-proxy/pkg/logger"
	"github.com/sklrsn/socks-proxy/pkg/socks"
)

const (
	socksPort int = 1080
)

func init() {
}

func main() {
	ss := socks.NewSocksServer(socks.WithPort(socksPort), socks.WithProto(socks.SOCKS5_VERSION))
	logger.Infof("Starting SOCKS proxy at:%v", socksPort)
	log.Fatalf("%v", ss.Start())
}
