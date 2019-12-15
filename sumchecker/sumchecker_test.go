package sumchecker_test

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"sync"
	"testing"

	"github.com/WillAbides/checksum/sumchecker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var knownHexSums = map[string]map[string]string{
	"sha256": {
		"foo": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
		"":    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	},
	"sha512": {
		"foo": "f7fbba6e0636f890e56fbbf3283e524c6fa3204ae298382d624741d0dc6638326e282c41be5e4254d8820772c5518a2c5a8c0c7f7eda19594a7eb539453e1ed7",
		"":    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
	},
	"sha1": {
		"foo": "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33",
		"":    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
	},
	"md5": {
		"foo": "acbd18db4cc2f85cedef654fccc4a4d8",
		"":    "d41d8cd98f00b204e9800998ecf8427e",
	},
}

func registerTestHashes(checker *sumchecker.SumChecker) {
	checker.RegisterHash("sha256", sha256.New)
	checker.RegisterHash("sha512", sha512.New)
	checker.RegisterHash("sha1", sha1.New)
	checker.RegisterHash("md5", md5.New)
}

func TestChecker_Sum(t *testing.T) {
	t.Run("known hashes", func(t *testing.T) {
		for hashName, sums := range knownHexSums {
			for input, wantHex := range sums {
				checker := new(sumchecker.SumChecker)
				registerTestHashes(checker)
				got, err := checker.Sum(hashName, []byte(input))
				assert.NoError(t, err)
				gotHex := hex.EncodeToString(got)
				assert.Equal(t, wantHex, gotHex)
			}
		}
	})

	t.Run("write error", func(t *testing.T) {
		checker := new(sumchecker.SumChecker)
		checker.RegisterHash("hsh", func() hash.Hash {
			t.Helper()
			return newErrHash(t, []byte("foo"))
		})
		got, err := checker.Sum("hsh", []byte("foo"))
		assert.Equal(t, assert.AnError, err)
		assert.Empty(t, got)
	})

	t.Run("invalid hash", func(t *testing.T) {
		checker := new(sumchecker.SumChecker)
		registerTestHashes(checker)
		got, err := checker.Sum("invalid", []byte("foo"))
		assert.Error(t, err)
		assert.Empty(t, got)
	})
}

func TestChecker_UnregisterHash(t *testing.T) {
	checker := new(sumchecker.SumChecker)
	registerTestHashes(checker)
	checker.UnregisterHash("sha1")
	_, err := checker.Sum("sha1", []byte("foo"))
	assert.EqualError(t, err, `no hash registered with the name "sha1"`)
}

func TestChecker_Validate(t *testing.T) {
	t.Run("known hashes", func(t *testing.T) {
		for hashName, sums := range knownHexSums {
			for input, wantHex := range sums {
				testName := fmt.Sprintf("%s %q", hashName, input)
				t.Run(testName, func(t *testing.T) {
					checker := new(sumchecker.SumChecker)
					registerTestHashes(checker)
					want, err := hex.DecodeString(wantHex)
					require.NoError(t, err)
					got, err := checker.Validate(hashName, want, []byte(input))
					assert.NoError(t, err)
					assert.True(t, got)
				})
			}
		}
	})

	t.Run("unregistered hash", func(t *testing.T) {
		checker := new(sumchecker.SumChecker)
		registerTestHashes(checker)
		got, err := checker.Validate("unregistered", []byte("bar"), []byte("foo"))
		assert.Error(t, err)
		assert.False(t, got)
	})

	t.Run("sync", func(t *testing.T) {
		var wg sync.WaitGroup
		checker := new(sumchecker.SumChecker)
		registerTestHashes(checker)
		for i := 0; i < 100; i++ {
			for hashName, sums := range knownHexSums {
				for input, wantHex := range sums {
					input := input
					wantHex := wantHex
					hashName := hashName
					wg.Add(1)
					go func() {
						want, err := hex.DecodeString(wantHex)
						require.NoError(t, err)
						got, err := checker.Validate(hashName, want, []byte(input))
						assert.NoError(t, err)
						assert.True(t, got)
						wg.Done()
					}()
				}
			}
		}
		wg.Wait()
	})
}

func newErrHash(t testing.TB, wantSum []byte) *errHash {
	return &errHash{
		t:       t,
		wantSum: wantSum,
	}
}

type errHash struct {
	t       testing.TB
	wantSum []byte
}

func (e *errHash) Write(p []byte) (n int, err error) {
	t := e.t
	t.Helper()
	assert.Equal(t, e.wantSum, p)
	return 0, assert.AnError
}

func (e *errHash) Sum(b []byte) []byte {
	panic("unexpected call")
}

func (e *errHash) Reset() {}

func (e *errHash) Size() int {
	panic("unexpected call")
}

func (e *errHash) BlockSize() int {
	panic("unexpected call")
}
