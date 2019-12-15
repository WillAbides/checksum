package knownsums

import (
	"errors"
	"testing"

	mocks "github.com/WillAbides/checksum/knownsums/_mocks"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestKnownSums_Add(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockSumChecker := mocks.NewMockSumChecker(ctrl)
		knownSums := &KnownSums{
			SumChecker: mockSumChecker,
		}
		data := []byte("foo")
		name := "sumname"
		hashName := "sumhash"
		hash := []byte("bar")
		want := []*knownSum{{
			Name:     name,
			HashName: hashName,
			Checksum: hash,
		}}
		mockSumChecker.EXPECT().Sum(hashName, data).Return(hash, nil)
		err := knownSums.Add(name, hashName, data)
		assert.NoError(t, err)
		assert.ElementsMatch(t, want, knownSums.knownSums)
	})

	t.Run("sum error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockSumChecker := mocks.NewMockSumChecker(ctrl)
		knownSums := &KnownSums{
			SumChecker: mockSumChecker,
		}
		data := []byte("foo")
		name := "sumname"
		hashName := "sumhash"
		mockSumChecker.EXPECT().Sum(hashName, data).Return(nil, assert.AnError)
		err := knownSums.Add(name, hashName, data)
		assert.Equal(t, assert.AnError, errors.Unwrap(err))
		assert.Empty(t, knownSums.knownSums)
	})

	t.Run("nil SumChecker", func(t *testing.T) {
		knownSums := &KnownSums{}
		data := []byte("foo")
		name := "sumname"
		hashName := "sumhash"
		err := knownSums.Add(name, hashName, data)
		assert.EqualError(t, err, "SumChecker cannot be nil")
		assert.Empty(t, knownSums.knownSums)
	})
}

func TestKnownSums_Validate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockSumChecker := mocks.NewMockSumChecker(ctrl)
		data := []byte("foo")
		name := "sumname"
		hashName := "sumhash"
		sum := []byte("bar")
		knownSums := &KnownSums{
			SumChecker: mockSumChecker,
			knownSums: []*knownSum{
				{
					Name:     name,
					HashName: hashName,
					Checksum: sum,
				},
			},
		}
		mockSumChecker.EXPECT().Validate(hashName, sum, data).Return(true, nil)
		got, err := knownSums.Validate(name, hashName, data)
		assert.NoError(t, err)
		assert.True(t, got)
	})

	t.Run("empty hashName", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockSumChecker := mocks.NewMockSumChecker(ctrl)
		data := []byte("foo")
		name := "sumname"
		knownSums := &KnownSums{
			SumChecker: mockSumChecker,
			knownSums: []*knownSum{
				{
					Name:     name,
					HashName: "hash1",
					Checksum: []byte("sum1"),
				},
				{
					Name:     name,
					HashName: "hash2",
					Checksum: []byte("sum2"),
				},
			},
		}
		mockSumChecker.EXPECT().Validate("hash1", []byte("sum1"), data).Return(true, nil)
		mockSumChecker.EXPECT().Validate("hash2", []byte("sum2"), data).Return(true, nil)
		got, err := knownSums.Validate(name, "", data)
		assert.NoError(t, err)
		assert.True(t, got)
	})

	t.Run("one of many invalid", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockSumChecker := mocks.NewMockSumChecker(ctrl)
		data := []byte("foo")
		name := "sumname"
		knownSums := &KnownSums{
			SumChecker: mockSumChecker,
			knownSums: []*knownSum{
				{
					Name:     name,
					HashName: "hash1",
					Checksum: []byte("sum1"),
				},
				{
					Name:     name,
					HashName: "hash2",
					Checksum: []byte("sum2"),
				},
				{
					Name:     name,
					HashName: "hash3",
					Checksum: []byte("sum3"),
				},
			},
		}
		mockSumChecker.EXPECT().Validate("hash1", []byte("sum1"), data).Return(true, nil).AnyTimes()
		mockSumChecker.EXPECT().Validate("hash2", []byte("sum2"), data).Return(false, nil)
		mockSumChecker.EXPECT().Validate("hash3", []byte("sum3"), data).Return(true, nil).AnyTimes()
		got, err := knownSums.Validate(name, "", data)
		assert.NoError(t, err)
		assert.False(t, got)
	})

	t.Run("one of many error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockSumChecker := mocks.NewMockSumChecker(ctrl)
		data := []byte("foo")
		name := "sumname"
		knownSums := &KnownSums{
			SumChecker: mockSumChecker,
			knownSums: []*knownSum{
				{
					Name:     name,
					HashName: "hash1",
					Checksum: []byte("sum1"),
				},
				{
					Name:     name,
					HashName: "hash2",
					Checksum: []byte("sum2"),
				},
				{
					Name:     name,
					HashName: "hash3",
					Checksum: []byte("sum3"),
				},
			},
		}
		mockSumChecker.EXPECT().Validate("hash1", []byte("sum1"), data).Return(true, nil).AnyTimes()
		mockSumChecker.EXPECT().Validate("hash2", []byte("sum2"), data).Return(false, assert.AnError)
		mockSumChecker.EXPECT().Validate("hash3", []byte("sum3"), data).Return(true, nil).AnyTimes()
		got, err := knownSums.Validate(name, "", data)
		assert.Equal(t, assert.AnError, errors.Unwrap(err))
		assert.False(t, got)
	})

	t.Run("nil checker", func(t *testing.T) {
		data := []byte("foo")
		name := "sumname"
		hashName := "sumhash"
		sum := []byte("bar")
		knownSums := &KnownSums{
			knownSums: []*knownSum{
				{
					Name:     name,
					HashName: hashName,
					Checksum: sum,
				},
			},
		}
		got, err := knownSums.Validate(name, hashName, data)
		assert.EqualError(t, err, "SumChecker cannot be nil")
		assert.False(t, got)
	})
}

func TestKnownSums_AddPrecalculatedSum(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		knownSums := &KnownSums{}
		name := "sumname"
		hashName := "sumhash"
		hash := []byte("bar")
		want := []*knownSum{{
			Name:     name,
			HashName: hashName,
			Checksum: hash,
		}}
		err := knownSums.AddPrecalculatedSum(name, hashName, hash)
		assert.NoError(t, err)
		assert.ElementsMatch(t, want, knownSums.knownSums)
	})

	t.Run("empty hashName", func(t *testing.T) {
		knownSums := &KnownSums{}
		err := knownSums.AddPrecalculatedSum("foo", "", []byte("foo"))
		assert.EqualError(t, err, "hashName cannot be empty")
		assert.Empty(t, knownSums.knownSums)
	})

	t.Run("duplicate", func(t *testing.T) {
		name := "sumname"
		hashName := "sumhash"
		knownSums := &KnownSums{
			knownSums: []*knownSum{{
				Name:     name,
				HashName: hashName,
				Checksum: []byte("foo"),
			}},
		}
		err := knownSums.AddPrecalculatedSum(name, hashName, []byte("bar"))
		assert.EqualError(t, err, "cannot add duplicate name and hashName")
		assert.Equal(t, []*knownSum{{
			Name:     name,
			HashName: hashName,
			Checksum: []byte("foo"),
		}}, knownSums.knownSums)
	})
}

func TestKnownSums_Remove(t *testing.T) {
	startSums := func() []*knownSum {
		return []*knownSum{
			{
				Name:     "foo",
				HashName: "bar",
			},
			{
				Name:     "foo",
				HashName: "qux",
			},
			{
				Name:     "baz",
				HashName: "qux",
			},
			{
				Name:     "baz",
				HashName: "bar",
			},
		}
	}

	t.Run("name and hashName exists", func(t *testing.T) {
		knownSums := &KnownSums{
			knownSums: startSums(),
		}
		want := []*knownSum{
			{
				Name:     "foo",
				HashName: "qux",
			},
			{
				Name:     "baz",
				HashName: "qux",
			},
			{
				Name:     "baz",
				HashName: "bar",
			},
		}
		knownSums.Remove("foo", "bar")
		assert.ElementsMatch(t, want, knownSums.knownSums)
	})

	t.Run("empty hashName removes all hashNames", func(t *testing.T) {
		knownSums := &KnownSums{
			knownSums: startSums(),
		}
		want := []*knownSum{
			{
				Name:     "baz",
				HashName: "qux",
			},
			{
				Name:     "baz",
				HashName: "bar",
			},
		}
		knownSums.Remove("foo", "")
		assert.ElementsMatch(t, want, knownSums.knownSums)
	})
}
