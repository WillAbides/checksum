package knownsums

import (
	"crypto"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKnownSums_MarshalJSON(t *testing.T) {
	ks := KnownSums{
		knownSums: []*knownSum{
			{
				Name:     "foo",
				Hash:     crypto.MD5,
				Checksum: []byte("baz"),
			},
			{
				Name:     "qux",
				Hash:     crypto.MD5,
				Checksum: []byte("bar"),
			},
		},
	}

	want := `
[
  {
    "name": "foo",
    "hash": "md5",
    "checksum": "62617a"
  },
  {
    "name": "qux",
    "hash": "md5",
    "checksum": "626172"
  }
]
`
	got, err := json.MarshalIndent(&ks, "", "  ")
	assert.NoError(t, err)
	assert.JSONEq(t, want, string(got))
}

func TestKnownSums_UnmarshalJSON(t *testing.T) {
	j := `
[
  {
    "name": "foo",
    "hash": "sha1",
    "checksum": "62617a"
  },
  {
    "name": "qux",
    "hash": "md5",
    "checksum": "626172"
  }
]
`
	want := KnownSums{
		knownSums: []*knownSum{
			{
				Name:     "foo",
				Hash:     crypto.SHA1,
				Checksum: []byte("baz"),
			},
			{
				Name:     "qux",
				Hash:     crypto.MD5,
				Checksum: []byte("bar"),
			},
		},
	}

	got := KnownSums{}
	err := json.Unmarshal([]byte(j), &got)
	assert.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestKnownSum_UnmarshalJSON(t *testing.T) {
	t.Run("single", func(t *testing.T) {
		j := `
{
  "name": "foo",
  "hash": "md5",
  "checksum": "62617a"
}
`
		want := knownSum{
			Name:     "foo",
			Hash:     crypto.MD5,
			Checksum: []byte("baz"),
		}

		var got knownSum
		err := json.Unmarshal([]byte(j), &got)
		assert.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("slice", func(t *testing.T) {
		j := `
[
  {
    "name": "foo",
    "hash": "sha1",
    "checksum": "62617a"
  },
  {
    "name": "qux",
    "hash": "md5",
    "checksum": "626172"
  }
]
`
		want := []*knownSum{
			{
				Name:     "foo",
				Hash:     crypto.SHA1,
				Checksum: []byte("baz"),
			},
			{
				Name:     "qux",
				Hash:     crypto.MD5,
				Checksum: []byte("bar"),
			},
		}

		var got []*knownSum

		err := json.Unmarshal([]byte(j), &got)
		assert.NoError(t, err)
		assert.Equal(t, want, got)
	})
}

func TestKnownSum_MarshalJSON(t *testing.T) {
	t.Run("single", func(t *testing.T) {
		ks := &knownSum{
			Name:     "foo",
			Hash:     crypto.MD5,
			Checksum: []byte("baz"),
		}
		want := `
{
  "name": "foo",
  "hash": "md5",
  "checksum": "62617a"
}
`
		got, err := json.MarshalIndent(ks, "", "  ")
		assert.NoError(t, err)
		assert.JSONEq(t, want, string(got))

	})

	t.Run("slice", func(t *testing.T) {
		ks := []*knownSum{
			{
				Name:     "foo",
				Hash:     crypto.MD5,
				Checksum: []byte("baz"),
			},
			{
				Name:     "qux",
				Hash:     crypto.MD5,
				Checksum: []byte("bar"),
			},
		}

		want := `
[
  {
    "name": "foo",
    "hash": "md5",
    "checksum": "62617a"
  },
  {
    "name": "qux",
    "hash": "md5",
    "checksum": "626172"
  }
]
`
		got, err := json.MarshalIndent(ks, "", "  ")
		assert.NoError(t, err)
		assert.JSONEq(t, want, string(got))
	})
}
