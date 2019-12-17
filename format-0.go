package iso_9564

import (
	"crypto/des"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

func NewFormat0(pan, pin, zpk string) PinBlock {
	return &pinBlockFormat0{
		pan: pan,
		pin: pin,
		zpk: zpk,
	}
}

func (f *pinBlockFormat0) Encrypt() (pinEncrypted string, err error) {

	clearPinBlock, err := f.generatePinBlock()
	if err != nil {
		return pinEncrypted, err
	}

	var ciphertext = make([]byte, len(clearPinBlock))
	zpk, err := hex.DecodeString(f.zpk)
	if err != nil {
		return pinEncrypted, err
	}

	var tripleDESKey []byte
	tripleDESKey = append(tripleDESKey, zpk[:16]...)
	tripleDESKey = append(tripleDESKey, zpk[:8]...)

	block, err := des.NewTripleDESCipher(tripleDESKey)
	if err != nil {
		return pinEncrypted, err
	}

	block.Encrypt(ciphertext, clearPinBlock)
	return hex.EncodeToString(ciphertext), nil
}

func (f *pinBlockFormat0) Decrypt(message string) (pin string, err error) {
	encryptedMessage, err := hex.DecodeString(message)
	if err != nil {
		return pin, err
	}

	zpk, err := hex.DecodeString(f.zpk)
	if err != nil {
		return pin, err
	}

	var tripleDESKey []byte
	tripleDESKey = append(tripleDESKey, zpk[:16]...)
	tripleDESKey = append(tripleDESKey, zpk[:8]...)

	block, err := des.NewTripleDESCipher(tripleDESKey)
	if err != nil {
		return pin, err
	}

	pinEncrypted := make([]byte, len(encryptedMessage))
	block.Decrypt(pinEncrypted, encryptedMessage)

	pin, err = f.decryptPinBlock(pinEncrypted)
	if err != nil {
		return pin, err
	}

	return pin, nil
}

func (f *pinBlockFormat0) decryptPinBlock(pinEncrypted []byte) (pin string, err error) {
	panBlockHex, err := f.panBlock(f.pan)
	if err != nil {
		return pin, err
	}

	dPan, err := hex.DecodeString(panBlockHex)
	if err != nil {
		return pin, err
	}

	var (
		dPin     = xor(dPan, pinEncrypted)
		pinBlock = hex.EncodeToString(dPin)
	)

	pin, err = f.decodePinBlock(pinBlock)
	if err != nil {
		return pin, err
	}
	return pin, nil
}

// Generate Clear Pin Block
func (f *pinBlockFormat0) generatePinBlock() (clearPinBlock []byte, err error) {

	var pinBlock = f.pinBlock(f.pin)
	panBlock, err := f.panBlock(f.pan)
	if err != nil {
		return clearPinBlock, err
	}

	dPin, err := hex.DecodeString(pinBlock)
	if err != nil {
		return clearPinBlock, err
	}

	dPan, err := hex.DecodeString(panBlock)
	if err != nil {
		return clearPinBlock, err
	}

	return xor(dPin, dPan), nil
}

// PIN = Personal Identity Number
func (f *pinBlockFormat0) pinBlock(pin string) string {
	var (
		pinLength   = len(pin)
		pinBlockHex = fmt.Sprintf(`0%v%s`, pinLength, pin)
	)
	return pinBlockHex + strings.Repeat("F", RADIX-len(pinBlockHex))
}

// PAN = Personal Account Number
func (f *pinBlockFormat0) panBlock(pan string) (panBLock string, err error) {
	var (
		maxPanLength = 12
		panLength    = len(pan)
	)

	if panLength < maxPanLength {
		return panBLock, fmt.Errorf("pan len is %v", panLength)
	}

	return fmt.Sprintf("0000%s", pan[panLength-maxPanLength-1:panLength-1]), nil
}

// PIN = Personal Identity Number
func (f *pinBlockFormat0) decodePinBlock(pinBlock string) (string, error) {
	const pinStartPosition = 2
	pinLength, err := strconv.Atoi(pinBlock[1:2])
	if err != nil {
		return "", err
	}
	return pinBlock[pinStartPosition : pinStartPosition+pinLength], nil
}

func xor(left, right []byte) []byte {
	var (
		leftLen  = len(left)
		rightLen = len(right)
		result   = make([]byte, len(left))
	)

	if leftLen == 0 || rightLen == 0 || rightLen != leftLen {
		return nil
	}

	for i := 0; i < len(left); i++ {
		result[i] = left[i] ^ right[i]
	}

	return result
}
