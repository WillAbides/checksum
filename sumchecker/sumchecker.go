package sumchecker

import (
	"bytes"
	"crypto"
	"fmt"
	"hash"
)

type HashRunner interface {
	WithHash(crypto.Hash, func(hash.Hash) error) error
}

type Checker struct {
	runner HashRunner
}

type defaultRunner struct{}

func (r *defaultRunner) WithHash(hsh crypto.Hash, fn func(hash.Hash) error) error {
	if !hsh.Available() {
		return fmt.Errorf("unregistered hash")
	}
	return fn(hsh.New())
}

func New(runner HashRunner) *Checker {
	if runner == nil {
		runner = new(defaultRunner)
	}
	return &Checker{
		runner: runner,
	}
}

var defaultChecker = New(nil)

func Checksum(hasher crypto.Hash, data []byte) ([]byte, error) {
	return defaultChecker.Checksum(hasher, data)
}

func (p *Checker) Checksum(hasher crypto.Hash, data []byte) ([]byte, error) {
	var sum []byte
	err := p.runner.WithHash(hasher, func(hsh hash.Hash) error {
		_, e := hsh.Write(data)
		if e != nil {
			return e
		}
		sum = hsh.Sum(nil)
		return nil
	})
	return sum, err
}

func ValidateChecksum(hasher crypto.Hash, wantSum []byte, data []byte) (bool, error) {
	return defaultChecker.ValidateChecksum(hasher, wantSum, data)
}

func (p *Checker) ValidateChecksum(hasher crypto.Hash, wantSum []byte, data []byte) (bool, error) {
	sum, err := p.Checksum(hasher, data)
	if err != nil {
		return false, err
	}
	return bytes.Equal(wantSum, sum), nil
}
