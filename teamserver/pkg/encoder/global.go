package encoder

import (
	"Havoc/pkg/colors"
	"Havoc/pkg/common/crypt"
	"Havoc/pkg/logger"
	"bytes"
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
		encHeader: []byte("HAVOC: enc"),
	}

	if e.FileEncrypted(path) {
		i := 0
		for i < 3 {
			logger.Info(colors.Blue("Enter passsowrd: "))
			pass, err := promptPassword()
			if err != nil {
				logger.Error("Read password Error:", colors.Red(err))
				os.Exit(1)
			}
			e.key = crypt.CreateHash(pass, crypt.DefaultParams)

			if d := e.decryptFile(path); len(d) != 0 {
				logger.Info(colors.Blue("Logged in"))
				time.Sleep(time.Millisecond * 1000)
				clearTerminal()
				break
			}
			logger.Info(colors.Red("Wrong password!"))
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
	pass1, _ := promptPassword()
	logger.Info(colors.Blue("Confirm passsowrd: "))
	pass2, _ := promptPassword()

	if bytes.Equal(pass1, pass2) {
		dec := DecryptFile(path)
		SetKey(pass1)
		enc := EncryptText(dec)
		err := os.WriteFile(path, enc, 0644)
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

func EncryptText(plainText []byte) []byte {
	return EncoderInstance.encryptText(plainText)
}

func DecryptText(plainText []byte) []byte {
	return EncoderInstance.decryptText(plainText)
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
