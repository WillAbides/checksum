package knownsums

import (
	"crypto"
	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/hex"
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

func mustHexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func TestKnownSums_Add(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		knownSums := &KnownSums{
			Checker: sumchecker.New(nil),
		}
		data := []byte("foo")
		name := "sumname"
		hash := crypto.MD5
		err := knownSums.Add(name, hash, data)
		assert.NoError(t, err)
		want := []*knownSum{
			{
				Hash:     hash,
				Name:     name,
				Checksum: mustHexDecode(t, knownHexSums["md5"]["foo"]),
			},
		}
		assert.Equal(t, want, knownSums.knownSums)
	})

	t.Run("unregistered hash", func(t *testing.T) {
		knownSums := &KnownSums{
			Checker: sumchecker.New(nil),
		}
		data := []byte("foo")
		name := "sumname"
		err := knownSums.Add(name, 999, data)
		assert.EqualError(t, err, "hash is not available")
		assert.Empty(t, knownSums.knownSums)
	})

	t.Run("nil Checker", func(t *testing.T) {
		knownSums := &KnownSums{}
		data := []byte("foo")
		name := "sumname"
		err := knownSums.Add(name, crypto.MD5, data)
		assert.EqualError(t, err, "checker cannot be nil")
		assert.Empty(t, knownSums.knownSums)
	})
}

func TestKnownSums_Validate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		data := []byte("foo")
		name := "sumname"
		hash := crypto.MD5
		knownSums := &KnownSums{
			Checker: sumchecker.New(nil),
			knownSums: []*knownSum{
				{
					Name:     name,
					Hash:     hash,
					Checksum: mustHexDecode(t, knownHexSums["md5"]["foo"]),
				},
			},
		}
		got, err := knownSums.Validate(name, &hash, data)
		assert.NoError(t, err)
		assert.True(t, got)
	})

	t.Run("nil hash", func(t *testing.T) {
		data := []byte("foo")
		name := "sumname"
		knownSums := &KnownSums{
			Checker: sumchecker.New(nil),
			knownSums: []*knownSum{
				{
					Name:     name,
					Hash:     crypto.MD5,
					Checksum: mustHexDecode(t, knownHexSums["md5"]["foo"]),
				},
				{
					Name:     name,
					Hash:     crypto.SHA1,
					Checksum: mustHexDecode(t, knownHexSums["sha1"]["foo"]),
				},
			},
		}
		got, err := knownSums.Validate(name, nil, data)
		assert.NoError(t, err)
		assert.True(t, got)
	})

	t.Run("one of many invalid", func(t *testing.T) {
		data := []byte("foo")
		name := "sumname"
		knownSums := &KnownSums{
			Checker: sumchecker.New(nil),
			knownSums: []*knownSum{
				{
					Name:     name,
					Hash:     crypto.MD5,
					Checksum: mustHexDecode(t, knownHexSums["md5"]["foo"]),
				},
				{
					Name:     name,
					Hash:     crypto.SHA1,
					Checksum: []byte("deadbeef"),
				},
				{
					Name:     name,
					Hash:     crypto.SHA256,
					Checksum: mustHexDecode(t, knownHexSums["sha256"]["foo"]),
				},
			},
		}
		got, err := knownSums.Validate(name, nil, data)
		assert.NoError(t, err)
		assert.False(t, got)
	})

	t.Run("unregistered hash in known sums", func(t *testing.T) {
		data := []byte("foo")
		name := "sumname"
		knownSums := &KnownSums{
			Checker: sumchecker.New(nil),
			knownSums: []*knownSum{
				{
					Name:     name,
					Hash:     999,
					Checksum: []byte("deadbeef"),
				},
			},
		}
		got, err := knownSums.Validate(name, nil, data)
		assert.NoError(t, err)
		assert.False(t, got)
	})

	t.Run("unregistered hash in arguments", func(t *testing.T) {
		data := []byte("foo")
		name := "sumname"
		knownSums := &KnownSums{
			Checker: sumchecker.New(nil),
			knownSums: []*knownSum{
				{
					Name:     name,
					Hash:     999,
					Checksum: []byte("deadbeef"),
				},
			},
		}
		hash := crypto.Hash(999)
		got, err := knownSums.Validate(name, &hash, data)
		assert.NoError(t, err)
		assert.False(t, got)
	})

	t.Run("nil checker", func(t *testing.T) {
		data := []byte("foo")
		name := "sumname"
		knownSums := &KnownSums{
			knownSums: []*knownSum{
				{
					Name:     name,
					Hash:     crypto.MD5,
					Checksum: []byte("foo"),
				},
			},
		}
		got, err := knownSums.Validate(name, nil, data)
		assert.EqualError(t, err, "checker cannot be nil")
		assert.False(t, got)
	})
}

func TestKnownSums_AddPrecalculatedSum(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		knownSums := &KnownSums{}
		name := "sumname"
		hash := crypto.MD5
		sum := []byte("bar")
		want := []*knownSum{{
			Name:     name,
			Hash:     hash,
			Checksum: sum,
		}}
		err := knownSums.AddPrecalculatedSum(name, hash, sum)
		assert.NoError(t, err)
		assert.ElementsMatch(t, want, knownSums.knownSums)
	})

	t.Run("duplicate", func(t *testing.T) {
		name := "sumname"
		hash := crypto.MD5
		knownSums := &KnownSums{
			knownSums: []*knownSum{{
				Name:     name,
				Hash:     hash,
				Checksum: []byte("foo"),
			}},
		}
		err := knownSums.AddPrecalculatedSum(name, hash, []byte("bar"))
		assert.EqualError(t, err, "cannot add duplicate name and hash")
		assert.Equal(t, []*knownSum{{
			Name:     name,
			Hash:     hash,
			Checksum: []byte("foo"),
		}}, knownSums.knownSums)
	})
}

func TestKnownSums_Remove(t *testing.T) {
	startSums := func() []*knownSum {
		return []*knownSum{
			{
				Name: "foo",
				Hash: crypto.MD5,
			},
			{
				Name: "foo",
				Hash: crypto.SHA256,
			},
			{
				Name: "baz",
				Hash: crypto.SHA256,
			},
			{
				Name: "baz",
				Hash: crypto.MD5,
			},
		}
	}

	t.Run("name and hashName exists", func(t *testing.T) {
		knownSums := &KnownSums{
			knownSums: startSums(),
		}
		want := []*knownSum{
			{
				Name: "foo",
				Hash: crypto.SHA256,
			},
			{
				Name: "baz",
				Hash: crypto.SHA256,
			},
			{
				Name: "baz",
				Hash: crypto.MD5,
			},
		}
		h := crypto.MD5
		knownSums.Remove("foo", &h)
		assert.ElementsMatch(t, want, knownSums.knownSums)
	})

	t.Run("empty hashName removes all hashNames", func(t *testing.T) {
		knownSums := &KnownSums{
			knownSums: startSums(),
		}
		want := []*knownSum{
			{
				Name: "baz",
				Hash: crypto.SHA256,
			},
			{
				Name: "baz",
				Hash: crypto.MD5,
			},
		}
		knownSums.Remove("foo", nil)
		assert.ElementsMatch(t, want, knownSums.knownSums)
	})
}
