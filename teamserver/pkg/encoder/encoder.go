package encoder

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"os"
	"os/exec"

	"Havoc/pkg/colors"
	"Havoc/pkg/common/crypt"
	"Havoc/pkg/logger"

	"golang.org/x/term"
)

type Encoder struct {
	key       []byte
	encHeader []byte
}

func (e *Encoder) encryptText(plainText []byte) []byte {
	if e.keyNotSet() {
		return plainText
	}

	block, err := aes.NewCipher(e.key)
	if err != nil {
		logger.Error("Encryption key Error: ", colors.Red(err))
		return []byte{}
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		logger.Error("Block generation Error: ", colors.Red(err))
		return []byte{}
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		logger.Error("Nonce generation Error: ", colors.Red(err))
		return []byte{}
	}
	cipherText := aesGCM.Seal(nil, nonce, plainText, nil)
	cipherText = append(nonce, cipherText...)
	cipherText = append(cipherText, e.encHeader...) // add encryption header to end of file

	return cipherText
}

func (e *Encoder) decryptText(cipherText []byte) []byte {
	if e.keyNotSet() {
		return cipherText
	}

	// remove encryption header from cipher text
	cipherText = cipherText[:len(cipherText)-len(e.encHeader)]

	block, err := aes.NewCipher(e.key)
	if err != nil {
		logger.Error("Decryption key Error: ", colors.Red(err))
		return []byte{}
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		logger.Error("Block generation Error: ", colors.Red(err))
		return []byte{}
	}

	var (
		// get nonce and encrypted text from cipher text
		nonceSize     = aesGCM.NonceSize()
		nonce         = cipherText[:nonceSize]
		encryptedText = cipherText[nonceSize:]
	)

	plainText, err := aesGCM.Open(nil, nonce, encryptedText, nil)
	if err != nil {
		logger.Error("Decryption Error: ", colors.Red(err))
		return []byte{}
	}

	return plainText
}

func (e *Encoder) encryptFile(path string) []byte {

	file, err := os.ReadFile(path)
	if err != nil {
		logger.Error("Read profile Error: ", colors.Red(err))
		return []byte{}
	}
	if e.keyNotSet() {
		return file
	}

	return e.encryptText(file)
}

func (e *Encoder) decryptFile(path string) []byte {
	file, err := os.ReadFile(path)
	if err != nil {
		logger.Error("Read profile Error: ", colors.Red(err))
		return []byte{}
	}
	if e.keyNotSet() {
		return file
	}

	return e.decryptText(file)
}

func (e *Encoder) FileEncrypted(path string) bool {
	file, err := os.ReadFile(path)
	if err != nil {
		logger.Error("Read profile Error: ", colors.Red(err))
		return false
	}

	header := file[len(file)-len(e.encHeader):]
	if bytes.Equal(e.encHeader, header) {
		return true
	}

	return false
}

func (e *Encoder) setKey(pass []byte) {
	e.key = crypt.CreateHash(pass, crypt.DefaultParams)
}

func (e *Encoder) keyNotSet() bool {
	if e.key == nil {
		return true
	}

	return false
}

func promptPassword() []byte {
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		logger.Error("Read password Error:", colors.Red(err))
		os.Exit(1)
	}

	return password
}

func clearTerminal() {
	cmd := exec.Command("clear")
	cmd.Stdout = os.Stdout
	cmd.Run()
}
