package sumchecker_test

import (
	"encoding/hex"
	"fmt"

	"github.com/WillAbides/checksum/sumchecker"
)

func Example() {
	checker := new(sumchecker.SumChecker)
	checker.RegisterHashes(sumchecker.CommonHashes)

	exampleData := []byte("foo bar")

	sum, err := checker.Sum("md5", exampleData)
	if err != nil {
		panic(err)
	}

	ok, err := checker.Validate("md5", sum, exampleData)
	if err != nil {
		panic(err)
	}

	fmt.Println(ok)
	fmt.Println(hex.EncodeToString(sum))

	// Output:
	// true
	// 327b6f07435811239bc47e1544353273
}
