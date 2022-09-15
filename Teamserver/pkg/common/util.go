package common

import (
    "bufio"
    "bytes"
    "fmt"
    "image/png"
    "io"
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

    u16s := make([]uint16, 1)

    ret := &bytes.Buffer{}

    b8buf := make([]byte, 4)

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