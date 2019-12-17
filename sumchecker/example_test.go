package sumchecker_test

import (
	"crypto"
	"encoding/hex"
	"fmt"

	"github.com/WillAbides/checksum/sumchecker"
)

func Example() {
	exampleData := []byte("foo bar")

	sum, err := sumchecker.Checksum(crypto.MD5, exampleData)
	if err != nil {
		panic(err)
	}

	ok, err := sumchecker.ValidateChecksum(crypto.MD5, sum, exampleData)
	if err != nil {
		panic(err)
	}

	fmt.Println(ok)
	fmt.Println(hex.EncodeToString(sum))

	// Output:
	// true
	// 327b6f07435811239bc47e1544353273
}
