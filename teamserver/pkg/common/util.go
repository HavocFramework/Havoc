package common

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"image/png"
	"io"
	"math/rand"
	"net"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"

	"Havoc/pkg/logger"

	"golang.org/x/image/bmp"
	"golang.org/x/text/encoding/unicode"
)

func Bmp2Png(BmpBytes []byte) []byte {
	var (
		f     io.Writer
		Bytes bytes.Buffer
	)

	f = bufio.NewWriter(&Bytes)

	Image, err := bmp.Decode(bytes.NewReader(BmpBytes))
	if err != nil {
		logger.Error("Failed to decode bmp: " + err.Error())
		return nil
	}

	err = png.Encode(f, Image)
	if err != nil {
		logger.Error("Failed to write png file: " + err.Error())
		return nil
	}

	return Bytes.Bytes()
}

func DecodeUTF16(b []byte) string {
	var (
		u16s  = make([]uint16, 1)
		b8buf = make([]byte, 4)
		ret   = &bytes.Buffer{}
	)

	lb := len(b)

	for i := 0; i < lb; i += 2 {
		u16s[0] = uint16(b[i]) + (uint16(b[i+1]) << 8)
		r := utf16.Decode(u16s)
		n := utf8.EncodeRune(b8buf, r[0])
		ret.Write(b8buf[:n])
	}

	return ret.String()
}

func EncodeUTF16(s string) string {
	var err error

	uni := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	encoded, err := uni.NewEncoder().String(s)
	if err != nil {
		logger.Error("Failed to convert UTF8 to UTF16")
		return ""
	}

	return encoded
}

func ByteCountSI(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB",
		float64(b)/float64(div), "kMGTPE"[exp])
}

func XorCipher(input, key string) (output string) {
	for i := 0; i < len(input); i++ {
		output += string(input[i] ^ key[i%len(key)])
	}

	return output
}

func RandomString(n int) string {
	var chars = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0987654321")
	str := make([]rune, n)
	for i := range str {
		str[i] = chars[rand.Intn(len(chars))]
	}
	return string(str)
}

func Int32ToLittle(x uint32) uint32 {
	bs := make([]byte, 4)
	binary.LittleEndian.PutUint32(bs, x)
	return binary.LittleEndian.Uint32(bs)
}

func StripNull(s string) string {
	return string(bytes.Trim([]byte(s), "\x00"))
}

func PercentageChange(part int, total int) float64 {
	return (float64(part) * float64(100)) / float64(total)
}

func IpStringToInt32(ip string) (int, error) {
	var long uint32
	err := binary.Read(bytes.NewBuffer(net.ParseIP(ip).To4()), binary.BigEndian, &long)
	if err != nil {
		return 0, err
	}
	return int(long), nil
}

func Int32ToIpString(ipInt int64) string {

	// need to do two bit shifting and “0xff” masking
	b0 := strconv.FormatInt((ipInt>>24)&0xff, 10)
	b1 := strconv.FormatInt((ipInt>>16)&0xff, 10)
	b2 := strconv.FormatInt((ipInt>>8)&0xff, 10)
	b3 := strconv.FormatInt(ipInt&0xff, 10)

	return b0 + "." + b1 + "." + b2 + "." + b3
}
