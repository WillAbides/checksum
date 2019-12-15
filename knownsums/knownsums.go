package knownsums

import (
	"fmt"
	"sync"
)

//go:generate mockgen -source knownsums.go -destination _mocks/knownsums_mocks.go -package _mocks

//SumChecker generates and validates checksums
//SumChecker is implemented by *SumChecker in github.com/WillAbides/checksum/sumchecker
type SumChecker interface {
	//Sum generates a checksum for data using a hash with the given hashName
	Sum(hashName string, data []byte) ([]byte, error)
	//Validate returns true if the sum generated for data matches wantSum
	Validate(hashName string, wantSum []byte, data []byte) (bool, error)
}

type knownSum struct {
	Name     string
	HashName string
	Checksum []byte
}

//KnownSums contains a list of checksums that can be validated with the Validate func
type KnownSums struct {
	sync.RWMutex
	SumChecker SumChecker
	knownSums  []*knownSum
}

//Add adds a checksum that can be validated by KnownSums.
//It uses KnownSums' SumChecker to calculate data's checksum.
func (c *KnownSums) Add(name, hashName string, data []byte) error {
	if c.SumChecker == nil {
		return fmt.Errorf("SumChecker cannot be nil")
	}
	sum, err := c.SumChecker.Sum(hashName, data)
	if err != nil {
		return fmt.Errorf("error calculating sum: %w", err)
	}
	return c.AddPrecalculatedSum(name, hashName, sum)
}

//AddPrecalculatedSum adds a sum that has already been calculated.
//This is primarily intended to be used for serialization
func (c *KnownSums) AddPrecalculatedSum(name, hashName string, sum []byte) error {
	c.Lock()
	defer c.Unlock()
	if hashName == "" {
		return fmt.Errorf("hashName cannot be empty")
	}
	existing := withNameAndHash(c.knownSums, name, hashName)
	if len(existing) != 0 {
		return fmt.Errorf("cannot add duplicate name and hashName")
	}
	c.knownSums = append(c.knownSums, &knownSum{
		Name:     name,
		HashName: hashName,
		Checksum: sum,
	})
	return nil
}

//Remove removes a checksum from KnownSums
func (c *KnownSums) Remove(name, hashName string) {
	c.Lock()
	defer c.Unlock()
	newSums := make([]*knownSum, 0, len(c.knownSums))
	for _, sum := range c.knownSums {
		if matchNameAndHash(name, hashName, sum) {
			continue
		}
		newSums = append(newSums, sum)
	}
	c.knownSums = newSums
}

//Validate returns true if data's checksum matches the sum stored in KnownSums.
//Looks for the known sum with the given name and hashName and uses SumChecker to validate that the sums match.
//If hashName is empty, it will return true if all known sums with the given name return true.
func (c *KnownSums) Validate(name string, hashName string, data []byte) (bool, error) {
	c.RLock()
	defer c.RUnlock()
	if c.SumChecker == nil {
		return false, fmt.Errorf("SumChecker cannot be nil")
	}
	sums := withNameAndHash(c.knownSums, name, hashName)
	var err error
	var ok bool
	for _, sum := range sums {
		ok, err = c.SumChecker.Validate(sum.HashName, sum.Checksum, data)
		if err != nil {
			err = fmt.Errorf(`error validating known sum %s: %w`, name, err)
			break
		}
		if !ok {
			break
		}
	}
	return ok, err
}

//returns true if sum.Name == name and hashName is either empty or matches sum.HashName
func matchNameAndHash(name, hashName string, sum *knownSum) bool {
	if sum == nil {
		return false
	}
	if hashName != "" && sum.HashName != hashName {
		return false
	}
	return sum.Name == name
}

//returns the subset of sums where matchNameAndHash is true
func withNameAndHash(sums []*knownSum, name, hashName string) []*knownSum {
	result := make([]*knownSum, 0, len(sums))
	for _, sum := range sums {
		if matchNameAndHash(name, hashName, sum) {
			result = append(result, sum)
		}
	}
	return result
}
