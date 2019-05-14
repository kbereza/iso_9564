# ISO 9564

A golang implementation [ISO 9564](https://en.wikipedia.org/wiki/ISO_9564)

## Supported formats:
* Format 0

## Example

```
package main

import (
	"fmt"
	"github.com/TakT/iso_9564"
)

const (
	pan = "5275605567847606"
	pin = "1580"
	zpk = "aa956f2a7f16c39997fcc48d62698d33"
)

func main() {
	var f0 = iso_9564.NewFormat0(pan, pin, zpk)
	pinEncrypted, err := f0.Encrypt()
	if err != nil {
		fmt.Println("err f0.Encrypt()", err)
		return
	}
	fmt.Println("pinEncrypted", pinEncrypted)
}
```

[Go Playground](https://play.golang.org/p/F93lt2JhGbe)