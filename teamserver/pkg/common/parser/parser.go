package parser

import (
	"encoding/binary"
	"Havoc/pkg/common"
	"Havoc/pkg/common/crypt"
)

type ReadType int

const (
	ReadInt32 ReadType = iota
	ReadInt64
	ReadBytes
	ReadPointer
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

func (p *Parser) CanIRead(ReadTypes []ReadType) bool {
	integer   := make([]byte, 4)
	number    := 0
	BytesRead := 0
	TotalSize := p.Length()
	
	for _, Type := range ReadTypes {
		switch Type {
		case ReadInt32:
			if TotalSize - BytesRead < 4 {
				return false
			}
			BytesRead += 4
		case ReadInt64:
			if TotalSize - BytesRead < 8 {
				return false
			}
			BytesRead += 8
		case ReadPointer:
			if TotalSize - BytesRead < 8 {
				return false
			}
			BytesRead += 8
		case ReadBytes:
			if TotalSize - BytesRead < 4 {
				return false
			}
			for i := range integer {
				integer[i] = 0
			}
			copy(integer, p.buffer[BytesRead:BytesRead+4])
			if p.bigEndian {
				number = int(binary.BigEndian.Uint32(integer))
			} else {
				number = int(binary.LittleEndian.Uint32(integer))
			}
			BytesRead += 4
			if TotalSize - BytesRead < number {
				return false
			}
			BytesRead += number
		}
	}
	return true
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

func (p *Parser) ParseInt64() int64 {
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
		return int64(binary.BigEndian.Uint64(integer))
	} else {
		return int64(binary.LittleEndian.Uint64(integer))
	}
}

func (p *Parser) ParsePointer() int64 {
	return p.ParseInt64()
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

func (p *Parser) ParseUTF16String() string {
	return common.StripNull(common.DecodeUTF16(p.ParseBytes()))
}

func (p *Parser) ParseString() string {
	return common.StripNull(string(p.ParseBytes()))
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
