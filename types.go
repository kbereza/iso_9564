package iso_9564

const (
	RADIX = 16
)

type (
	PinBlock interface {
		Encrypt() (string, error)
		Decrypt(message string) (string, error)
	}

	pinBlockFormat0 struct {
		pan, pin, zpk string
	}
)
