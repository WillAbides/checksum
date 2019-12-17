package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/WillAbides/checksum/cachecopy"
	"github.com/WillAbides/checksum/knownsums"
	"github.com/WillAbides/checksum/sumchecker"
)

var sumChecker *sumchecker.SumChecker

func init() {
	sumChecker = new(sumchecker.SumChecker)
	sumChecker.RegisterHash("sha1", sha1.New)
	sumChecker.RegisterHash("sha256", sha256.New)
	sumChecker.RegisterHash("sha512", sha512.New)
	sumChecker.RegisterHash("md5", md5.New)
}

func errOut(format string, a ...interface{}) {
	_, _ = fmt.Fprintf(os.Stderr, format, a...)
}

func exitErr(format string, a ...interface{}) {
	errOut(format, a...)
	os.Exit(1)
}

func main() {
	var hsh string

	flag.StringVar(&hsh, "a", "sha256", "Hash algorithm to use.  One of sha1, sha256, sha512 or md5.")

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

	ks := knownsums.KnownSums{
		SumChecker: sumChecker,
	}

	err = ks.AddPrecalculatedSum("default", hsh, wantSum)
	if err != nil {
		exitErr("error: %v\n", err)
	}

	var validated bool

	copier := &cachecopy.Copier{
		Cache: cachecopy.NewBufferCache(nil),
		Validator: func(rdr io.Reader) bool {
			b, err := ioutil.ReadAll(rdr)
			if err != nil {
				exitErr("error reading input stream: %v\n", err)
				return false
			}
			got, err := ks.Validate("default", hsh, b)
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
		exitErr("input did not match the checksum %x using the hash algorithm %s\n", wantSum, hsh)
	}
}
