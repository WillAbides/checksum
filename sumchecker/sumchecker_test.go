package sumchecker_test

import (
	"crypto"
	"encoding/hex"
	"testing"

	"github.com/WillAbides/checksum/sumchecker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var knownHexSums = map[crypto.Hash]map[string]string{
	crypto.SHA256: {
		"foo": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
		"":    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	},
	crypto.SHA512: {
		"foo": "f7fbba6e0636f890e56fbbf3283e524c6fa3204ae298382d624741d0dc6638326e282c41be5e4254d8820772c5518a2c5a8c0c7f7eda19594a7eb539453e1ed7",
		"":    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
	},
	crypto.SHA1: {
		"foo": "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33",
		"":    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
	},
	crypto.MD5: {
		"foo": "acbd18db4cc2f85cedef654fccc4a4d8",
		"":    "d41d8cd98f00b204e9800998ecf8427e",
	},
}

func TestChecksum(t *testing.T) {
	t.Run("known hashes", func(t *testing.T) {
		for hsh, sums := range knownHexSums {
			for input, wantHex := range sums {
				got, err := sumchecker.Checksum(hsh, []byte(input))
				assert.NoError(t, err)
				gotHex := hex.EncodeToString(got)
				assert.Equal(t, wantHex, gotHex)
			}
		}
	})
}

func TestValidateChecksum(t *testing.T) {
	t.Run("known hashes", func(t *testing.T) {
		for hsh, sums := range knownHexSums {
			for input, wantHex := range sums {
				want, err := hex.DecodeString(wantHex)
				require.NoError(t, err)
				got, err := sumchecker.ValidateChecksum(hsh, want, []byte(input))
				assert.NoError(t, err)
				assert.True(t, got)

				got, err = sumchecker.ValidateChecksum(hsh, want, []byte(input+"bogus"))
				assert.NoError(t, err)
				assert.False(t, got)
			}
		}
	})
}
