package knownsums

import (
	"crypto"
	"fmt"
	"sync"
)

type Checker interface {
	Checksum(hasher crypto.Hash, data []byte) ([]byte, error)
	ValidateChecksum(hasher crypto.Hash, wantSum []byte, data []byte) (bool, error)
}

type knownSum struct {
	Hash     crypto.Hash
	Name     string
	Checksum []byte
}

//KnownSums contains a list of checksums that can be validated with the Validate func
type KnownSums struct {
	sync.RWMutex
	Checker   Checker
	knownSums []*knownSum
}

//Add adds a checksum that can be validated by KnownSums.
//It uses KnownSums' SumChecker to calculate data's checksum.
func (c *KnownSums) Add(name string, hash crypto.Hash, data []byte) error {
	if c.Checker == nil {
		return fmt.Errorf("checker cannot be nil")
	}
	if !hash.Available() {
		return fmt.Errorf("hash is not available")
	}
	sum, err := c.Checker.Checksum(hash, data)
	if err != nil {
		return fmt.Errorf("error calculating sum: %w", err)
	}
	return c.AddPrecalculatedSum(name, hash, sum)
}

//AddPrecalculatedSum adds a sum that has already been calculated.
//This is primarily intended to be used for serialization
func (c *KnownSums) AddPrecalculatedSum(name string, hash crypto.Hash, sum []byte) error {
	c.Lock()
	defer c.Unlock()
	existing := withNameAndHash(c.knownSums, name, &hash)
	if len(existing) != 0 {
		return fmt.Errorf("cannot add duplicate name and hash")
	}
	c.knownSums = append(c.knownSums, &knownSum{
		Name:     name,
		Hash:     hash,
		Checksum: sum,
	})
	return nil
}

//Remove removes a checksum from KnownSums
func (c *KnownSums) Remove(name string, hash *crypto.Hash) {
	c.Lock()
	defer c.Unlock()
	newSums := make([]*knownSum, 0, len(c.knownSums))
	for _, sum := range c.knownSums {
		if matchNameAndHash(name, hash, sum) {
			continue
		}
		newSums = append(newSums, sum)
	}
	c.knownSums = newSums
}

//Validate returns true if data's checksum matches the sum stored in KnownSums.
//Looks for the known sum with the given name and hashName and uses SumChecker to validate that the sums match.
//If hashName is empty, it will return true if all known sums with the given name return true.
func (c *KnownSums) Validate(name string, hash *crypto.Hash, data []byte) (bool, error) {
	c.RLock()
	defer c.RUnlock()
	if c.Checker == nil {
		return false, fmt.Errorf("checker cannot be nil")
	}
	sums := withNameAndHash(c.knownSums, name, hash)
	var err error
	var ok bool
	for _, sum := range sums {
		if !sum.Hash.Available() {
			continue
		}
		ok, err = c.Checker.ValidateChecksum(sum.Hash, sum.Checksum, data)
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

//returns true if sum.Name == name and hash is either nil or matches sum.HashName
func matchNameAndHash(name string, hash *crypto.Hash, sum *knownSum) bool {
	if sum == nil {
		return false
	}
	if hash != nil && sum.Hash != *hash {
		return false
	}
	return sum.Name == name
}

func withNameAndHash(sums []*knownSum, name string, hash *crypto.Hash) []*knownSum {
	result := make([]*knownSum, 0, len(sums))
	for _, sum := range sums {
		if matchNameAndHash(name, hash, sum) {
			result = append(result, sum)
		}
	}
	return result
}
