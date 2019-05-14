package iso_9564

import (
	"testing"
)

const (
	// good data
	pan = "5275605567847606"
	pin = "1580"
	zpk = "aa956f2a7f16c39997fcc48d62698d33"

	pinEncryptedString = "bfeff18f48c3a09c"

	// bad data
	badPan = "5275605"
	badZPK = "241415a"
)

func TestNewFormat0(t *testing.T) {
	var f0 = NewFormat0(pan, pin, zpk)
	pinEncrypted, err := f0.Encrypt()
	if err != nil {
		t.Fatalf("encrypt error: %s", err)
	}

	if pinEncrypted != pinEncryptedString {
		t.Fatalf("expected %s, actual %s", pinEncryptedString, pinEncrypted)
	}
}

func TestNewFormat0IncorrectPan(t *testing.T) {
	var f0 = NewFormat0(badPan, pin, zpk)
	_, err := f0.Encrypt()
	if err != nil && err.Error() == "pan len is 7" {
		t.Logf("pass: wrong PAN: %s", err)
		return
	}
	t.Fatalf("err: %s", err)
}

func TestNewFormat0IncorrectZPK(t *testing.T) {

	var f0 = NewFormat0(pan, pin, badZPK)
	_, err := f0.Encrypt()
	if err != nil && err.Error() == "encoding/hex: odd length hex string" {
		t.Logf("pass: wrong ZPK: %s", err)
		return
	}
	t.Fatalf("err: %s", err)
}
