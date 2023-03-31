package socks

import (
	"errors"
	"net"
	"strings"
)

type Socks struct {
	listener net.Listener
	addr     string
	handler  func(s *Socks, conn net.Conn)
	Failed   bool
	Clients  []int32
}

func NewSocks(addr string) *Socks {
	var socks = new(Socks)

	if !strings.Contains(addr, ":") {
		return nil
	}

	socks.addr = addr

	return socks
}

func (s *Socks) SetHandler(handler func(s *Socks, conn net.Conn)) {

	s.handler = handler

}

func (s *Socks) Start() error {
	var (
		err error
		con net.Conn
	)

	if s.handler == nil {
		return errors.New("handler not specified")
	}

	/* listen on the specified addr */
	if s.listener, err = net.Listen("tcp", s.addr); err != nil {
		return err
	}

	for {

		/* accepts any new connections */
		if con, err = s.listener.Accept(); err != nil {
			return err
		}

		go s.handler(s, con)

	}
}

func (s *Socks) Close() {

	if s.listener != nil {
		s.listener.Close()
	}

}
