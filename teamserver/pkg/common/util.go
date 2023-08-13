package common

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"image/png"
	"time"
	"io"
	"math/rand"
	"net"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
	"regexp"
	"errors"
	"strings"

	"Havoc/pkg/logger"

	"golang.org/x/image/bmp"
	"golang.org/x/text/encoding/unicode"
)

func ParseWorkingHours(WorkingHours string) (int32, error) {
	/*
	 * The working hours are packed in a uint32
	 * X: enabled or not
	 * A: start hour
	 * B: start minute
	 * C: end hour
	 * D: end minute
	 *          XAAAAABBBBBBCCCCCDDDDDD
	 * 00000000010000011111100000111111
	 * ------------32 bits-------------
	 */
	 var (
	 	IntWorkingHours int32 = 0
	 )

	if WorkingHours != "" {
		match, err := regexp.MatchString("^[12]?[0-9]:[0-6][0-9]-[12]?[0-9]:[0-6][0-9]$", WorkingHours)
		if err != nil || match == false {
			return IntWorkingHours, errors.New("Failed to parse the WorkingHours: Invalid format for working hours, use: 8:00-17:00")
		}

		startAndEnd         := strings.Split(WorkingHours, "-")
		startHourandMinutes := strings.Split(startAndEnd[0], ":")
		endHourandMinutes   := strings.Split(startAndEnd[1], ":")

		startHour, _ := strconv.Atoi(startHourandMinutes[0])
		startMin , _ := strconv.Atoi(startHourandMinutes[1])
		endHour,   _ := strconv.Atoi(endHourandMinutes[0])
		endMin,    _ := strconv.Atoi(endHourandMinutes[1])

		if startHour < 0 || startHour > 24 || endHour < 0 || endHour > 24 || startMin < 0 || startMin > 60 || endMin < 0 || endMin > 60 {
			return IntWorkingHours, errors.New("Failed to parse the WorkingHours: Invalid hour or minute defined in working hours")
		}

		if endHour < startHour || (startHour == endHour && endMin <= startMin) {
			return IntWorkingHours, errors.New("Failed to parse the WorkingHours: Then end hour can't be sooner than the start hour")
		}

		// set the "enabled" bit
		IntWorkingHours |= 1 << 22
		IntWorkingHours |= (int32(startHour) & 0b011111) << 17
		IntWorkingHours |= (int32(startMin)  & 0b111111) << 11
		IntWorkingHours |= (int32(endHour)   & 0b011111) << 6
		IntWorkingHours |= (int32(endMin)    & 0b111111) << 0
	}

	return IntWorkingHours, nil
}

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

	// in C, strings terminate with a null-byte
	if strings.HasSuffix(s, "\x00") == false {
		s += "\x00"
	}
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

func PercentageChange(part int, total int64) float64 {
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

func EpochTimeToSystemTime( EpochTime int64 ) int64 {
	var (
		UNIX_TIME_START  int64 = 0x019DB1DED53E8000 //January 1, 1970 (start of Unix epoch) in "ticks"
		TICKS_PER_SECOND int64 = 10000000 //a tick is 100ns
	)

	if (EpochTime == 0) {
		return 0
	}

	return ( EpochTime * TICKS_PER_SECOND ) + UNIX_TIME_START
}

func GetRandomChar(dict string) string {
    return string(dict[rand.Intn(len(dict))])
}

// generate a PipeName from a name template
func GeneratePipeName(Template string, PID int, TID int) string {
	var PipeName = Template

	hexdigits := "0123456789abcdef"
	digits := "0123456789"
	ascii_uppercase := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	ascii_lowercase := "abcdefghijklmnopqrstuvwxyz"

	rand.Seed(time.Now().UnixNano())

	// add the process PID (if specified)
	if PID != 0 {
		PipeName = strings.Replace(PipeName, "{pid}", fmt.Sprintf("%d", PID), -1)
		PipeName = strings.Replace(PipeName, "{Pid}", fmt.Sprintf("%d", PID), -1)
		PipeName = strings.Replace(PipeName, "{PID}", fmt.Sprintf("%d", PID), -1)
	}

	// add the process TID (if specified)
	if TID != 0 {
		PipeName = strings.Replace(PipeName, "{tid}", fmt.Sprintf("%d", TID), -1)
		PipeName = strings.Replace(PipeName, "{Tid}", fmt.Sprintf("%d", TID), -1)
		PipeName = strings.Replace(PipeName, "{TID}", fmt.Sprintf("%d", TID), -1)
	}

	// #: hex char
	for strings.Contains(PipeName, "$") {
		PipeName = strings.Replace(PipeName, "$", GetRandomChar(hexdigits), 1)
	}

	// #: number
	for strings.Contains(PipeName, "#") {
		PipeName = strings.Replace(PipeName, "#", GetRandomChar(digits), 1)
	}

	// !: uppercase char
	for strings.Contains(PipeName, "@") {
		PipeName = strings.Replace(PipeName, "@", GetRandomChar(ascii_uppercase), 1)
	}

	// !: lowercase char
	for strings.Contains(PipeName, "!") {
		PipeName = strings.Replace(PipeName, "!", GetRandomChar(ascii_lowercase), 1)
	}

	// make sure the pipename starts with \\.\pipe\
	if strings.HasPrefix(PipeName, "\\\\.\\pipe\\") == false {
		PipeName = "\\\\.\\pipe\\" + PipeName
	}

	return PipeName
}

func GetInterfaceIpv4Addr(interfaceOrIp string) string {
	var (
		ief      *net.Interface
		addrs    []net.Addr
		ipv4Addr net.IP
		err      error
	)
	if ief, err = net.InterfaceByName(interfaceOrIp); err != nil { // get interface
		return interfaceOrIp
	}
	if addrs, err = ief.Addrs(); err != nil { // get addresses
		return interfaceOrIp
	}
	for _, addr := range addrs { // get ipv4 address
		if ipv4Addr = addr.(*net.IPNet).IP.To4(); ipv4Addr != nil {
			break
		}
	}
	if ipv4Addr == nil {
		return interfaceOrIp
	}
	return ipv4Addr.String()
}
