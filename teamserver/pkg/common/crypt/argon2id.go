package crypt

import (
	"encoding/base64"
	"golang.org/x/crypto/argon2"
)

// Modified version of agithub.com/alexedwards/argon2id

// DefaultParams provides some default parameters for hashing passwords.
var DefaultParams = &Params{
	Memory:    64 * 1024,
	Time:      1,
	Threads:   1,
	SaltLength:16,
	KeyLength: 32,
}

type Params struct {
	// The amount of memory used by the algorithm (in kibibytes).
	// For example memory=64*1024 sets the memory cost to ~64 MB.
	// If using that amount of memory (64 MB) is not possible in some contexts
	// then the time parameter can be increased to compensate.
	Memory uint32

	// The number of iterations over the memory.
	Time uint32

	// The number of threads (or lnaes) used by the algorithm.
	// Recommended value is between 1 and runtime.NumCPU().
	Threads uint8

	// Length of the random salt. 16 bytes is recommended for password hashing.
	SaltLength uint32

	// Length of the generated key. 16 bytes or more is recommended.
	// The key argument should be the AES key, either 16, 24, or 32 bytes
	// to select AES-128, AES-192, or AES-256.
	KeyLength uint32
}

func CreateHash(password []byte, params *Params, salt []byte) ([]byte, []byte) {
	if salt == nil {
		salt = RandomBytes(params.SaltLength)
	}
	saltB64 : = make([]byte, base64.StdEncoding.EncodedLen(len(salt)))
	base64.StdEncoding.Encode(saltB64,salt)
	
	return argon2.IDKey(password, salt, params.Time, params.Memory, params.Threads, params.KeyLength), saltB64
}

func RandomBytes(n uint32) []byte{
	buff := make([]byte, n)
	_, err := rand.Read(buff)
	if err != nil{
		logger.Error("Buffer Error:", err)
		os.Exit(1)
	}
	return buff
}