package cachecopy

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const lorem = `
Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna 
aliqua. Faucibus scelerisque eleifend donec pretium vulputate sapien. A iaculis at erat pellentesque adipiscing 
commodo elit at. Proin libero nunc consequat interdum varius sit amet. Tincidunt augue interdum velit euismod in. 
Aliquam ut porttitor leo a diam sollicitudin tempor. Eu scelerisque felis imperdiet proin fermentum leo vel orci. Eget 
duis at tellus at urna condimentum mattis pellentesque. Augue lacus viverra vitae congue eu consequat ac felis. Magna 
fermentum iaculis eu non diam phasellus vestibulum lorem. Metus vulputate eu scelerisque felis. Eget mi proin sed 
libero enim sed faucibus turpis. Habitant morbi tristique senectus et. Morbi tristique senectus et netus et malesuada 
fames ac. Diam quis enim lobortis scelerisque.

`

func loremBuf(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	for i := 0; i < 100; i++ {
		_, err := buf.WriteString(lorem)
		require.NoError(t, err)
	}
	return &buf
}

func tmpFile(t *testing.T) (*os.File, func()) {
	t.Helper()
	file, err := ioutil.TempFile("", "")
	require.NoError(t, err)
	return file, func() {
		require.NoError(t, os.Remove(file.Name()))
	}
}

var failingValidator = func(reader io.Reader) (bool, string) {
	return false, "failing validator always fails"
}

var failingValidatorErr = &ValidatorError{msg: "failing validator always fails"}

func loremValidator(t *testing.T) func(reader io.Reader) (bool, string) {
	t.Helper()
	return func(rdr io.Reader) (bool, string) {
		t.Helper()
		got, e := ioutil.ReadAll(rdr)
		require.NoError(t, e)
		return bytes.Equal(got, loremBuf(t).Bytes()), ""
	}
}

func TestCopy(t *testing.T) {
	t.Run("buffer", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			var buf bytes.Buffer
			cache := NewBufferCache(&buf)
			var dst bytes.Buffer
			validator := loremValidator(t)
			_, err := Copy(&dst, loremBuf(t), validator, cache)
			assert.NoError(t, err)
			assert.Equal(t, loremBuf(t).String(), dst.String())
		})

		t.Run("invalid", func(t *testing.T) {
			var buf bytes.Buffer
			cache := NewBufferCache(&buf)
			var dst bytes.Buffer
			_, err := Copy(&dst, loremBuf(t), failingValidator, cache)
			assert.Equal(t, failingValidatorErr, err)
			assert.Empty(t, dst.String())
		})
	})

	t.Run("file", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			cacheFile, cacheTeardown := tmpFile(t)
			defer cacheTeardown()
			cache := NewFileCache(cacheFile)
			var dst bytes.Buffer
			validator := loremValidator(t)
			_, err := Copy(&dst, loremBuf(t), validator, cache)
			assert.NoError(t, err)
			assert.Equal(t, loremBuf(t).String(), dst.String())
		})

		t.Run("invalid", func(t *testing.T) {
			cacheFile, cacheTeardown := tmpFile(t)
			defer cacheTeardown()
			cache := NewFileCache(cacheFile)
			var dst bytes.Buffer
			_, err := Copy(&dst, loremBuf(t), failingValidator, cache)
			assert.Equal(t, failingValidatorErr, err)
			assert.Empty(t, dst.String())
		})
	})
}
