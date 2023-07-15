package encoder

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
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
	profilePath string
	key       []byte
	salt      []byte
	encHeader []byte
	Decrypt   bool
}

func (e *Encoder) encryptText(plainText []byte) []byte {
	if e.keyNotSet() || e.Decrypt {
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
	cipherText = append(cipherText, e.salt...)
	cipherText = append(cipherText, e.encHeader...)
	return cipherText
}

func (e *Encoder) decryptText(cipherText []byte) []byte {
	if e.keyNotSet() || e.Decrypt {
		return cipherText
	}

	// remove encryption header and salt from cipher text
	cipherText = cipherText[:len(cipherText)-len(e.encHeader)-len(e.salt)]

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

func (e *Encoder) encryptFile(path string, write bool) []byte {
	file, err := os.ReadFile(path)
	if err != nil {
		logger.Error("Read profile Error: ", colors.Red(err))
		return []byte{}
	}
	if e.keyNotSet() || e.Decrypt || e.fileEncrypted(path) {
		return file
	}

	enc := e.encryptText(file)
	if write {
		if err := os.WriteFile(path, enc, 0644); err != nil {
			logger.Error("Write decrypted file Error: ", colors.Red(err))
			return []byte{}
		}
	}
	return enc
}

func (e *Encoder) decryptFile(path string, write bool) []byte {
	file, err := os.ReadFile(path)
	if err != nil {
		logger.Error("Read encrypted file Error: ", colors.Red(err))
		return []byte{}
	}
	if e.keyNotSet() || e.Decrypt || !e.fileEncrypted(path){
		return file
	}

	dec := e.decryptText(file)
	if write {
		if err := os.WriteFile(path, dec, 0644); err != nil {
			logger.Error("Write decrypted file Error: ", colors.Red(err))
			return []byte{}
		}
	}
	return dec
}

func (e *Encoder) fileEncrypted(path string) bool {
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

func (e *Encoder) keyNotSet() bool {
	if e.key == nil {
		return true
	}

	return false
}

func (e *Encoder) setKey(pass []byte, path string) {
        salt := e.saltFromFile(path)
        e.key, e.salt = crypt.CreateHash(pass, crypt.DefaultParams, salt)
}

func(e *Encoder) saltFromFile(path string) []byte{
	if path == "" || !e.fileEncrypted(path) {
		return nil
	}

	file, err := os.ReadFile(path)
	if err != nil{
		logger.Error(err)
		os.Exit(1)
	}
	saltB64 := file[len(file)-len(e.encHeader)-crypt.B64SaltLenght():len(file)-len(e.encHeader)]
	salt, _ := base64.StdEncoding.DecodeString(string(saltB64))

	return []byte(salt)
}

func(e *Encoder) overwriteBytes(data []byte) {
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
