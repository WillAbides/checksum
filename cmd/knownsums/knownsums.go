package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"

	"github.com/WillAbides/checksum/knownsums"
	"github.com/WillAbides/checksum/sumchecker"
	"github.com/alecthomas/kong"
)

type existingChecksums struct {
	Checksums string `kong:"required,type=existingfile,short='c',help='checksums file'"`
}

var sumCheckerOnce sync.Once
var _sumChecker *sumchecker.SumChecker

func sumChecker() *sumchecker.SumChecker {
	sumCheckerOnce.Do(func() {
		_sumChecker = new(sumchecker.SumChecker)
		_sumChecker.RegisterHash("sha1", sha1.New)
		_sumChecker.RegisterHash("sha256", sha256.New)
		_sumChecker.RegisterHash("sha512", sha512.New)
		_sumChecker.RegisterHash("md5", md5.New)
	})
	return _sumChecker
}

func (c existingChecksums) knownSums() (*knownsums.KnownSums, error) {
	sums := knownsums.KnownSums{
		SumChecker: sumChecker(),
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
	Algorithm string `kong:"short=a,enum='sha1,sha256,sha512,md5',default=sha256"`
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
	err = checksums.Add(c.NameFileAlgo.name(), c.NameFileAlgo.Algorithm, data)
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
	got, err := checksums.Validate(c.NameFileAlgo.name(), c.NameFileAlgo.Algorithm, data)
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
	kctx := kong.Parse(&cli)
	err := kctx.Run()
	kctx.FatalIfErrorf(err)
}
