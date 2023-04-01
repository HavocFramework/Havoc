package socks

import (
	"bufio"
	"encoding/binary"
	"errors"
	"net"
	"fmt"
)

type Socks5AuthTypes byte
type HostIpTypes byte

const (
	Version byte = 0x5
)

const (
	NoAuth   byte = 0
	GssApi   byte = 1
	UserPass byte = 2
	NoMatch  byte = 0xff
)

const (
	IPv4   byte = 1
	Domain byte = 3
	IPv6   byte = 4
)

type SocksHeader struct {
	Version  byte
	Command  byte
	RSV      byte
	ATYP     byte
	IpDomain []byte
	Port     uint16
}

type NegotiationHeader struct {
	Version  byte
	NMethods byte
	Methods  []byte
}

func SubNegotiationClient(conn net.Conn) (NegotiationHeader, error) {
	var (
		header     NegotiationHeader
		reader     = bufio.NewReader(conn)
		err        error
		NumMethods byte
	)

	/*
     * Client Version identifier/method selection message
     * +----+----------+----------+
     * |VER | NMETHODS | METHODS  |
     * +----+----------+----------+
    */

	header.Version, err = reader.ReadByte()
	if err != nil {
		return header, err
	}

	/* check if it's a socks5 header */
	if header.Version != 0x5 {
		return header, errors.New(fmt.Sprint("socks version (%d) is not 5 (0x5)", header.Version))
	}

	header.NMethods, err = reader.ReadByte()
	if err != nil {
		return header, err
	}

	NumMethods = header.NMethods

	for NumMethods != 0 {
		var AuthType byte
		AuthType, err = reader.ReadByte()
		if err != nil {
			return header, err
		}
		header.Methods = append(header.Methods, AuthType)
		NumMethods -= 1
	}
	return header, nil
}

func ReadSocksHeader(conn net.Conn) (SocksHeader, error) {
	var (
		header SocksHeader
		reader = bufio.NewReader(conn)
		err    error
	)

	/*
     * From rfc 1928 (S4), the SOCKS request is formed as follows:
     *
     *    +----+-----+-------+------+----------+----------+
     *    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
     *    +----+-----+-------+------+----------+----------+
     *    | 1  |  1  | X'00' |  1   | Variable |    2     |
     *    +----+-----+-------+------+----------+----------+
     *
     * Where:
     *
     *      o  VER    protocol version: X'05'
     *      o  CMD
     *         o  CONNECT X'01'
     *         o  BIND X'02'
     *         o  UDP ASSOCIATE X'03'
     *      o  RSV    RESERVED
     *      o  ATYP   address type of following address
     *         o  IP V4 address: X'01'
     *         o  DOMAINNAME: X'03'
     *         o  IP V6 address: X'04'
     *      o  DST.ADDR       desired destination address
     *      o  DST.PORT desired destination port in network octet
     *         order
	 */

	header.Version, err = reader.ReadByte()
	if err != nil {
		return header, err
	}

	/* check if it's a socks5 header */
	if header.Version != 0x5 {
		return header, errors.New(fmt.Sprint("socks version (%d) is not 5 (0x5)", header.Version))
	}

	header.Command, err = reader.ReadByte()
	if err != nil {
		return header, err
	}

	/* check if it's a CONNECT command */
	if header.Command != 0x1 {
		return header, err
	}

	header.RSV, err = reader.ReadByte()
	if err != nil {
		return header, err
	}

	if header.RSV != 0x0 {
		return header, errors.New(fmt.Sprint("socks RSV (%d) is not 0 (0x0)", header.RSV))
	}

	header.ATYP, err = reader.ReadByte()
	if err != nil {
		return header, errors.New("ATYP puto el que lee")
	}

	if header.ATYP == 0x1 {
		// IP V4 address
		header.IpDomain = make([]byte, 4)
		n, err := reader.Read(header.IpDomain)
		if err != nil {
			return header, err
		}
		if n != 4 {
			return header, errors.New("failed to read the IPv4 address")
		}
	} else if header.ATYP == 0x3 {
		// DOMAINNAME
		var DomainLength byte
		DomainLength, err = reader.ReadByte()
		if err != nil {
			return header, err
		}
		header.IpDomain = make([]byte, uint32(DomainLength))
		n, err := reader.Read(header.IpDomain)
		if err != nil {
			return header, err
		}
		if uint32(n) != uint32(DomainLength) {
			return header, errors.New("failed to read the domain")
		}
	} else if header.ATYP == 0x4 {
		// IP V6 address
		header.IpDomain = make([]byte, 16)
		n, err := reader.Read(header.IpDomain)
		if err != nil {
			return header, err
		}
		if n != 16 {
			return header, errors.New("failed to read the IPv6 address")
		}
	} else {
		return header, errors.New(fmt.Sprint("socks ATYP (%d) is not valid", header.ATYP))
	}

	PortArr := make([]byte, 2)

	PortArr[0], err = reader.ReadByte()
	if err != nil {
		return header, err
	}

	PortArr[1], err = reader.ReadByte()
	if err != nil {
		return header, err
	}

	header.Port = binary.BigEndian.Uint16(PortArr)

	return header, nil
}
