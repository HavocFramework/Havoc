package parser

import (
	"encoding/binary"

	"Havoc/pkg/common/crypt"
)

type Parser struct {
	buffer    []byte
	bigEndian bool
}

func NewParser(buffer []byte) *Parser {
	var parser = new(Parser)
	parser.buffer = buffer
	parser.bigEndian = true
	return parser
}

func (p *Parser) ParseInt32() int {
	var integer = make([]byte, 4)

	for i := range integer {
		integer[i] = 0
	}

	if p.Length() >= 4 {
		if p.Length() == 4 {
			copy(integer, p.buffer[:p.Length()])
			p.buffer = []byte{}
		} else {
			copy(integer, p.buffer[:p.Length()-4])
			p.buffer = p.buffer[4:]
		}
	}

	if p.bigEndian {
		return int(binary.BigEndian.Uint32(integer))
	} else {
		return int(binary.LittleEndian.Uint32(integer))
	}
}

func (p *Parser) ParseInt64() int {
	var integer = make([]byte, 8)

	for i := range integer {
		integer[i] = 0
	}

	if p.Length() >= 8 {
		if p.Length() == 8 {
			copy(integer, p.buffer[:p.Length()])
			p.buffer = []byte{}
		} else {
			copy(integer, p.buffer[:p.Length()-8])
			p.buffer = p.buffer[8:]
		}
	}

	if p.bigEndian {
		return int(binary.BigEndian.Uint64(integer))
	} else {
		return int(binary.LittleEndian.Uint64(integer))
	}
}

func (p *Parser) SetBigEndian(bigEndian bool) {
	p.bigEndian = bigEndian
}

func (p *Parser) ParseBytes() []byte {
	var bytesBuffer []byte

	if p.Length() >= 4 {
		BytesSize := uint(p.ParseInt32())
		if BytesSize > uint(p.Length()) {
			bytesBuffer, p.buffer = p.buffer[:p.Length()], p.buffer[p.Length():]
		} else {
			bytesBuffer, p.buffer = p.buffer[:BytesSize], p.buffer[BytesSize:]
		}
	}

	return bytesBuffer
}

func (p *Parser) ParseAtLeastBytes(NumberOfBytes int) []byte {
	var bytesBuffer []byte

	if NumberOfBytes > p.Length() {
		bytesBuffer, p.buffer = p.buffer[:len(p.buffer)], p.buffer[len(p.buffer):]
	} else {
		bytesBuffer, p.buffer = p.buffer[:NumberOfBytes], p.buffer[NumberOfBytes:]
	}

	return bytesBuffer
}

func (p *Parser) Length() int {
	return len(p.buffer)
}

func (p *Parser) Buffer() []byte {
	return p.buffer
}

func (p *Parser) DecryptBuffer(AESKey []byte, AESIv []byte) {
	p.buffer = crypt.XCryptBytesAES256(p.buffer, AESKey, AESIv)
}
