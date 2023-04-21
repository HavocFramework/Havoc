package packer

import (
    "bytes"
    "encoding/binary"

    "Havoc/pkg/common"
    "Havoc/pkg/common/crypt"
    "Havoc/pkg/logger"
)

// TODO: rework this

type Packer struct {
    data []byte
    size int

    AesKey []byte
    AesIV  []byte
}

func NewPacker(AesKey, AesIV []byte) *Packer {
    var packer = new(Packer)
    packer.AesKey = AesKey
    packer.AesIV = AesIV
    return packer
}

func (p *Packer) AddInt64(data int64) {
    var buffer = make([]byte, 8)
    binary.LittleEndian.PutUint64(buffer, uint64(data))
    p.data = append(p.data, buffer...)

    p.size += 8
}

func (p *Packer) AddInt32(data int32) {
    var buffer = make([]byte, 4)
    binary.LittleEndian.PutUint32(buffer, uint32(data))
    p.data = append(p.data, buffer...)

    p.size += 4
}

func (p *Packer) AddInt(data int) {
    var buffer = make([]byte, 4)
    binary.LittleEndian.PutUint32(buffer, uint32(data))
    p.data = append(p.data, buffer...)

    p.size += 4
}

// AddUInt32 use a much as possible this function
func (p *Packer) AddUInt32(data uint32) {
    var buffer = make([]byte, 4)
    binary.LittleEndian.PutUint32(buffer, data)
    p.data = append(p.data, buffer...)

    p.size += 4
}

func (p *Packer) AddString(data string) {
    var buffer = make([]byte, 4)
    binary.LittleEndian.PutUint32(buffer, uint32(len(data)))
    p.data = append(p.data, buffer...)
    p.data = append(p.data, []byte(data)...)

    p.size += 4
    p.size += len(data)
}

func (p *Packer) AddWString(data string) {
    p.AddString(common.EncodeUTF16(data))
}

func (p *Packer) AddBytes(data []byte) {
    var buffer = make([]byte, 4)
    binary.LittleEndian.PutUint32(buffer, uint32(len(data)))
    p.data = append(p.data, buffer...)
    p.data = append(p.data, data...)

    p.size += 4
    p.size += len(data)
}

func (p *Packer) Build() []byte {
    var Temp = make([]byte, 32)

    if bytes.Compare(p.AesKey, Temp) == 0 {
        return p.data
    }

    logger.Debug("No Aes Key specified")
    if (p.AesKey != nil) || (p.AesIV != nil) {
        p.data = crypt.XCryptBytesAES256(p.data, p.AesKey, p.AesIV)
    }

    return p.data
}

func (p *Packer) Buffer() []byte {
    return p.data
}

func (p *Packer) Size() int {
    return p.size
}

func (p *Packer) AddOwnSizeFirst() {
    var oldData = p.data
    p.AddInt(len(oldData))
    p.AddBytes(oldData)

    p.size += 4
}
