package encoder

import (
	"Havoc/pkg/colors"
	"Havoc/pkg/common/crypt"
	"Havoc/pkg/logger"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"os"
	"time"
)

var EncoderInstance *Encoder

func Initialize(path string) {
	EncoderInstance = newEncoder(path)
}

func newEncoder(path string) *Encoder {
	e := &Encoder{
		key:       nil,
		encHeader: []byte(base64.StdEncoding.EncodeToString([]byte("HAVOC: enc"))),
		Decrypt:   false,
	}

	// check if profile is encrypted if so prompt password
	if e.FileEncrypted(path) {
		i := 0
		for i < 3 {
			logger.Info(colors.Blue("Enter passsowrd: "))
			pass := promptPassword()
			e.key = crypt.CreateHash(pass, crypt.DefaultParams)
			OverwriteBytes(pass)

			if d := e.decryptFile(path); len(d) != 0 {
				logger.Info(colors.Blue("Logged in"))
				time.Sleep(time.Millisecond * 1000)
				clearTerminal()
				break
			}
			logger.Info(colors.Red("Wrong password!"))
			OverwriteBytes(e.key)
			e.key = nil

			i++
		}
		if i == 3 {
			logger.Info(colors.Red("Too many wrong attempts!"))
			os.Exit(1)
		}
	}

	return e
}

func ChangePassword(path string) {
	logger.Info(colors.Blue("Enter new passsowrd: "))
	pass1 := promptPassword()
	logger.Info(colors.Blue("Confirm passsowrd: "))
	pass2 := promptPassword()

	if bytes.Equal(pass1, pass2) {
		d := DecryptFile(path)
		SetKey(pass1)
		e := EncryptText(d)

		OverwriteBytes(pass1)
		OverwriteBytes(pass2)

		err := os.WriteFile(path, e, 0644)
		if err != nil {
			logger.Error("Config Error:", colors.Red(err))
			os.Exit(1)
		}

		logger.Info(colors.Blue("Password changed"))
		time.Sleep(time.Millisecond * 1000)
		clearTerminal()
		return
	}
	logger.Info(colors.Blue("Passwords doesn't match"))
	os.Exit(1)
}
func SetKey(pass []byte) {
	EncoderInstance.setKey(pass)
}

func EncryptText(text []byte) []byte {
	return EncoderInstance.encryptText(text)
}

func DecryptText(text []byte) []byte {
	return EncoderInstance.decryptText(text)
}

func EncryptFile(path string) []byte {
	return EncoderInstance.encryptFile(path)
}

func DecryptFile(path string) []byte {
	return EncoderInstance.decryptFile(path)
}

func FileEncrypted(path string) bool {
	return EncoderInstance.FileEncrypted(path)
}

func KeyNotSet() bool {
	return EncoderInstance.keyNotSet()
}

func OverwriteBytes(data []byte) {
	randomBytes := make([]byte, len(data))
	if _, err := rand.Read(randomBytes); err != nil {
		logger.Error("Byte generation Error:", colors.Red(err))
		os.Exit(1)
	}

	for i := range data {
		data[i] = randomBytes[i]
	}
	for i := range randomBytes {
		randomBytes[i] = 0
	}
}
