package sumchecker

import (
	"bytes"
	"fmt"
	"hash"
	"sync"
)

type hashPool struct {
	pool sync.Pool
}

func (h *hashPool) get() hash.Hash {
	return h.pool.Get().(hash.Hash)
}

func (h *hashPool) put(hsh hash.Hash) {
	hsh.Reset()
	h.pool.Put(hsh)
}

//SumChecker will generate or validate checksums using any registered hash.Hash.
type SumChecker struct {
	_hashes    map[string]*hashPool
	hashesMux  sync.RWMutex
	hashesOnce sync.Once
}

func (h *SumChecker) hashes() map[string]*hashPool {
	h.hashesOnce.Do(func() {
		h._hashes = map[string]*hashPool{}
	})
	return h._hashes
}

func (h *SumChecker) withHash(hashName string, fn func(hash.Hash) error) error {
	h.hashesMux.RLock()
	defer h.hashesMux.RUnlock()
	pool := h.hashes()[hashName]
	if pool == nil {
		return fmt.Errorf("no hash registered with the name %q", hashName)
	}
	hsh := pool.get()
	defer pool.put(hsh)
	return fn(hsh)
}

//RegisterHash registers a hash.Hash to be used with SumChecker.
func (h *SumChecker) RegisterHash(hashName string, newHash func() hash.Hash) {
	h.hashesMux.Lock()
	defer h.hashesMux.Unlock()
	h.hashes()[hashName] = &hashPool{
		pool: sync.Pool{
			New: func() interface{} {
				return newHash()
			},
		},
	}
}

//UnregisterHash removes a registered hash
func (h *SumChecker) UnregisterHash(hashName string) {
	h.hashesMux.Lock()
	defer h.hashesMux.Unlock()
	delete(h.hashes(), hashName)
}

//Sum returns data's hash.Sum() using the hash registered as hashName
func (h *SumChecker) Sum(hashName string, data []byte) ([]byte, error) {
	var sum []byte
	err := h.withHash(hashName, func(hsh hash.Hash) error {
		_, e := hsh.Write(data)
		if e != nil {
			return e
		}
		sum = hsh.Sum(nil)
		return nil
	})
	return sum, err
}

//Validate runs SumChecker.Sum() and validates that the result matches wantSum
func (h *SumChecker) Validate(hashName string, wantSum []byte, data []byte) (bool, error) {
	sum, err := h.Sum(hashName, data)
	if err != nil {
		return false, err
	}
	return bytes.Equal(wantSum, sum), nil
}