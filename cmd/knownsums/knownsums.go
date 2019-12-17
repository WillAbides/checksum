package main

import (
	"crypto"
	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/WillAbides/checksum/knownsums"
	"github.com/WillAbides/checksum/knownsums/hashnames"
	"github.com/WillAbides/checksum/sumchecker"
	"github.com/alecthomas/kong"
)

type existingChecksums struct {
	Checksums string `kong:"required,type=existingfile,short='c',help='checksums file'"`
}

func (c existingChecksums) knownSums() (*knownsums.KnownSums, error) {
	sums := knownsums.KnownSums{
		Checker: sumchecker.New(nil),
	}
	b, err := ioutil.ReadFile(c.Checksums)
	if err != nil {
		return &sums, err
	}
	err = json.Unmarshal(b, &sums)
	if err != nil {
		return &sums, err
	}
	return &sums, err
}

type mainCmd struct {
	Add      addCmd      `kong:"cmd"`
	Validate validateCmd `kong:"cmd"`
	Init     initCmd     `kong:"cmd"`
}

type initCmd struct {
	Checksums string `kong:"required,type=file,short='c',help='checksums file'"`
}

func fileExists(filename string) (bool, error) {
	_, err := os.Stat(filename)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func (c *initCmd) Run() error {
	exists, err := fileExists(c.Checksums)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("%s already exists", c.Checksums)
	}
	return writeKnownSumsToFile(&knownsums.KnownSums{}, c.Checksums)
}

type nameFileAlgo struct {
	File      string `kong:"arg,existingfile"`
	Name      string `kong:"arg,optional"`
	Algorithm string `kong:"short=a,enum=${algo_enum},default=${algo_default},help=${algo_help}"`
}

func (n nameFileAlgo) hash() crypto.Hash {
	return hashnames.LookupHash(n.Algorithm)
}

func (n nameFileAlgo) name() string {
	if n.Name != "" {
		return n.Name
	}
	return filepath.Base(n.File)
}

type addCmd struct {
	NameFileAlgo      nameFileAlgo      `kong:"embed"`
	ExistingChecksums existingChecksums `kong:"embed"`
}

type validateCmd struct {
	NameFileAlgo      nameFileAlgo      `kong:"embed"`
	ExistingChecksums existingChecksums `kong:"embed"`
}

func writeKnownSumsToFile(sums *knownsums.KnownSums, filename string) error {
	b, err := json.MarshalIndent(&sums, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filename, b, 0640)
}

func (c *addCmd) Run() error {
	checksums, err := c.ExistingChecksums.knownSums()
	if err != nil {
		return err
	}
	data, err := ioutil.ReadFile(c.NameFileAlgo.File)
	if err != nil {
		return err
	}
	err = checksums.Add(c.NameFileAlgo.name(), c.NameFileAlgo.hash(), data)
	if err != nil {
		return err
	}
	return writeKnownSumsToFile(checksums, c.ExistingChecksums.Checksums)
}

func (c *validateCmd) Run() error {
	checksums, err := c.ExistingChecksums.knownSums()
	if err != nil {
		return err
	}
	data, err := ioutil.ReadFile(c.NameFileAlgo.File)
	if err != nil {
		return err
	}
	hsh := c.NameFileAlgo.hash()
	got, err := checksums.Validate(c.NameFileAlgo.name(), &hsh, data)
	if err != nil {
		return err
	}
	if !got {
		return fmt.Errorf("checksum for %s did not match", c.NameFileAlgo.File)
	}
	return nil
}

var cli mainCmd

func main() {
	vars := kong.Vars{
		"algo_enum":    strings.Join(hashnames.AvailableHashNames(), ","),
		"algo_default": hashnames.HashName(crypto.SHA256),
		"algo_help":    fmt.Sprintf("The hash algorithm to use.  One of %s", strings.Join(hashnames.AvailableHashNames(), ", ")),
	}
	kctx := kong.Parse(&cli, vars)
	err := kctx.Run()
	kctx.FatalIfErrorf(err)
}
