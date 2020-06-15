package aesr

import (
	"io/ioutil"
	"strings"
	"testing"
)

func TestEncrypt(t *testing.T) {
	srcstring := "plainText"
	r := strings.NewReader(srcstring)
	key := randomByteSecure(32)
	encrypted, err := Encrypt(r, key)
	if err != nil {
		t.Errorf("got %v want %v", err, nil)
	}
	decrypted, err := Decrypt(encrypted, key)
	if err != nil {
		t.Errorf("got %v want %v", err, nil)
	}
	b, err := ioutil.ReadAll(decrypted)
	if err != nil {
		t.Errorf("got %v want %v", err, nil)
	}
	if srcstring != string(b) {
		t.Errorf("got %v want %v", string(b), srcstring)
	}

}
