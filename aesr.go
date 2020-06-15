package aesr

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"fmt"
	"io"
)

func randomByteSecure(n int) []byte {
	b := make([]byte, n)
	crand.Read(b)
	return b
}

func make_iv() []byte {
	return randomByteSecure(16)
}

// Encrypt returns encryptedReader AESCTRmode using `key`. `key` is []byte(length 32).
// Encrypt generates IV automatically.
// Returned reader has IV as first 16 bytes.
func Encrypt(src io.Reader, key []byte) (io.Reader, error) {
	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := make_iv()
	ivr := bytes.NewReader(iv)
	stream := cipher.NewCTR(cipherBlock, iv)
	streamReader := &cipher.StreamReader{
		S: stream,
		R: src,
	}
	mr := io.MultiReader(ivr, streamReader)
	return mr, nil
}

// Encrypt returns decryptedReader AESCTRmode using `key`.
// Encrypt assumes first 16 bytes of src is IV.
func Decrypt(src io.Reader, key []byte) (io.Reader, error) {
	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, 16)
	n, _ := src.Read(iv)
	if n != 16 {
		return nil, fmt.Errorf("noIV")
	}
	stream := cipher.NewCTR(cipherBlock, iv)
	streamReader := &cipher.StreamReader{
		S: stream,
		R: src,
	}
	return streamReader, nil
}
