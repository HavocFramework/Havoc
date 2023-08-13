package utils

import (
    "encoding/base64"
    "encoding/binary"
    "unicode/utf16"
    "fmt"
    "math/rand"
    "os"
    "strconv"
    "strings"
    "time"
    "unsafe"

    "Havoc/pkg/logger"
)

const letterBytes = "abcdef0123456789"
const (
    letterIdxBits = 4
    letterIdxMask = 1<<letterIdxBits - 1
    letterIdxMax  = 63 / letterIdxBits
)

func UTF16BytesToString(b []byte) string {
    size := (len(b) - 2) / 2
    utf := make([]uint16, size)
    for i := 0; i < size; i += 1 {
        utf[i] = binary.LittleEndian.Uint16(b[i*2:])
    }
    return string(utf16.Decode(utf))
}

func GenerateID(n int) string {
    var src = rand.NewSource(time.Now().UnixNano())
    b := make([]byte, n)
    // A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
    for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
        if remain == 0 {
            cache, remain = src.Int63(), letterIdxMax
        }
        if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
            b[i] = letterBytes[idx]
            i--
        }
        cache >>= letterIdxBits
        remain--
    }

    return string(b)
}

func GenerateString(min int, max int) string {
    rand.Seed(time.Now().UnixNano())
    length := min + rand.Intn(max - min + 1)
    var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
    b := make([]rune, length)
    for i := range b {
        b[i] = letterRunes[rand.Intn(len(letterRunes))]
    }

    return string(b)
}

func EncodeCommand(x string) string {
    encodedCMD := base64.StdEncoding.EncodeToString([]byte(x))
    return encodedCMD
}

func IP2Inet(ipaddr string) uint32 {
    var (
        ip                 = strings.Split(ipaddr, ".")
        ip1, ip2, ip3, ip4 uint64
        ret                uint32
    )
    ip1, _ = strconv.ParseUint(ip[0], 10, 8)
    ip2, _ = strconv.ParseUint(ip[1], 10, 8)
    ip3, _ = strconv.ParseUint(ip[2], 10, 8)
    ip4, _ = strconv.ParseUint(ip[3], 10, 8)
    ret = uint32(ip4)<<24 + uint32(ip3)<<16 + uint32(ip2)<<8 + uint32(ip1)
    return ret
}

func Port2Htons(port uint16) uint16 {
    b := make([]byte, 2)
    binary.BigEndian.PutUint16(b, port)
    return *(*uint16)(unsafe.Pointer(&b[0]))
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

func GetTeamserverPath() string {
    var (
        Path string
        err  error
    )

    if Path, err = os.Getwd(); err != nil {
        logger.Error("Couldn't get current working directory of teamserver: " + err.Error())
        return ""
    }

    return Path
}

/*func GetFieldName(fieldPinter interface{}) (name string) {
    val := reflect.ValueOf(structPoint).Elem()
    val2 := reflect.ValueOf(fieldPinter).Elem()

    for i := 0; i < val.NumField(); i++ {
        valueField := val.Field(i)
        if valueField.Addr().Interface() == val2.Addr().Interface() {
            return val.Type().Field(i).Name
        }
    }
    return
}*/

func IntToHexString(Int int) string {
    return fmt.Sprintf("%x", Int)
}

func HexIntToString(HexInt int) string {
    var bs = make([]byte, 4)
    binary.LittleEndian.PutUint32(bs, uint32(HexInt))
    return fmt.Sprintf("%x", binary.BigEndian.Uint32(bs))
}

func HexIntToBigEndian(HexInt int) int {
    var bs = make([]byte, 4)
    binary.LittleEndian.PutUint32(bs, uint32(HexInt))
    return int(binary.BigEndian.Uint32(bs))
}