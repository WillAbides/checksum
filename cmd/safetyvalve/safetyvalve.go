package main

import (
	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/WillAbides/checksum/cachecopy"
	"github.com/WillAbides/checksum/knownsums/hashnames"
	"github.com/WillAbides/checksum/sumchecker"
)

func errOut(format string, a ...interface{}) {
	_, _ = fmt.Fprintf(os.Stderr, format, a...)
}

func exitErr(format string, a ...interface{}) {
	errOut(format, a...)
	os.Exit(1)
}

func main() {
	var hashName string

	flag.StringVar(&hashName, "a", "sha256", "Hash algorithm to use.  One of sha1, sha256, sha512 or md5.")

	flag.Usage = func() {
		errOut(`
safetyvalve reads from stdin, verifies that data received matched the given 
checksum, then writes to stdout. When the checksum does not match, safetyvalve 
returns 1 and writes nothing to stdout.

Usage of %s:

	%s [options] checksum

Options:

`, filepath.Base(os.Args[0]), os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	info, err := os.Stdin.Stat()
	if err != nil {
		panic(err)
	}

	if info.Mode()&os.ModeCharDevice != 0 {
		flag.Usage()
		errOut("\n\n¡nothing piped to stdin!\n")
		os.Exit(2)
	}

	wantSum, err := hex.DecodeString(flag.Arg(0))
	if err != nil {
		exitErr("checksum must be a hex value\n")
	}
	hsh := hashnames.LookupHash(hashName)
	var validated bool

	copier := &cachecopy.Copier{
		Cache: cachecopy.NewBufferCache(nil),
		Validator: func(rdr io.Reader) bool {
			b, err := ioutil.ReadAll(rdr)
			if err != nil {
				exitErr("error reading input stream: %v\n", err)
				return false
			}
			got, err := sumchecker.ValidateChecksum(hsh, wantSum, b)
			if err != nil {
				exitErr("error validating the checksum: %v\n", err)
				return false
			}
			validated = got
			return got
		},
	}

	_, err = copier.Copy(os.Stdout, os.Stdin)
	if err != nil {
		exitErr("error copying to stdout: %v\n", err)
	}

	if !validated {
		exitErr("input did not match the checksum %x using the hash algorithm %s\n", wantSum, hashName)
	}
}
