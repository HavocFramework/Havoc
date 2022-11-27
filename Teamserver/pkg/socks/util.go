package socks

import (
	"Havoc/pkg/logger"
	"bufio"
	"encoding/binary"
	"errors"
	"net"
)

type SocksHeader struct {
	Version byte
	Command byte
	Port    uint32
	IP      uint32
	Domain  []byte
}

func ReadSocksHeader(conn net.Conn) (SocksHeader, error) {
	var (
		header SocksHeader
		reader = bufio.NewReader(conn)
		size   = 0
		err    error
	)

	size = 8
	peek, err := reader.Peek(size)
	if err != nil {
		return header, err
	}

	/* check if it's a socks header */
	if peek[0x0] != 0x4 {
		return header, errors.New("socks version is not 4 (0x4)")
	}
	header.Version = peek[0x0]

	/* check if it's a socks header */
	if peek[0x1] != 0x1 {
		return header, errors.New("socks command is not connect (0x1)")
	}
	header.Command = peek[0x1]

	header.Port = uint32(binary.BigEndian.Uint16(peek[2:4]))

	/* get the ip bytes */
	peek = peek[4:8]
	header.IP = binary.LittleEndian.Uint32(peek)

	/* if we specified a host then peek that too */
	if peek[0x0] == 0x0 && peek[0x1] == 0x0 && peek[0x2] == 0x0 && peek[0x3] == 0x1 {
		logger.Info("Parse host too")
		err = nil

		size = 12

		/* now read host */
		for {

			size++
			peek, err = reader.Peek(size)
			if err != nil {
				break
			}

			/* stop at null terminator */
			if peek[len(peek)-1] == 0x0 {
				break
			}

		}

		header.IP = 1
		header.Domain = peek[9:]
	}

	return header, err
}
