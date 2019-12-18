package cachecopy

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

type Cache interface {
	io.WriteCloser
	Reader() (io.ReadCloser, error)
}

type Validator func(io.Reader) (bool, string)

type ValidatorError struct {
	msg string
}

func (e *ValidatorError) Error() string {
	if e.msg == "" {
		return "validator returned false with no message"
	}
	return fmt.Sprintf("validator returned false with the message: %q", e.msg)
}

type Copier struct {
	Cache     Cache
	Validator Validator
}

func (c *Copier) Copy(dst io.Writer, src io.Reader) (int64, error) {
	return Copy(dst, src, c.Validator, c.Cache)
}

func NewBufferCache(buf *bytes.Buffer) Cache {
	if buf == nil {
		buf = new(bytes.Buffer)
	}
	return &bufferCache{
		Buffer: *buf,
	}
}

type bufferCache struct {
	bytes.Buffer
}

func (c *bufferCache) Reader() (io.ReadCloser, error) {
	return ioutil.NopCloser(bytes.NewReader(c.Buffer.Bytes())), nil
}

func (c *bufferCache) Close() error {
	return nil
}

func NewFileCache(file *os.File) Cache {
	return &fileCache{
		File: *file,
	}
}

type fileCache struct {
	os.File
}

func (c *fileCache) Reader() (io.ReadCloser, error) {
	return os.Open(c.File.Name())
}

func Copy(dst io.Writer, src io.Reader, validator func(io.Reader) (bool, string), cache Cache) (written int64, err error) {
	if validator == nil {
		return written, fmt.Errorf("validator cannot be nil")
	}
	if cache == nil {
		cache = NewBufferCache(nil)
	}
	defer func() {
		_ = cache.Close()
	}()
	_, err = io.Copy(cache, src)
	if err != nil {
		return written, fmt.Errorf("error copying to cache")
	}
	vReader, err := cache.Reader()
	if err != nil {
		return written, fmt.Errorf("error getting cache reader")
	}
	ok, validatorMsg := validator(vReader)
	_ = vReader.Close()
	if !ok {
		return written, &ValidatorError{msg: validatorMsg}
	}
	rdr, err := cache.Reader()
	if err != nil {
		return written, fmt.Errorf("error getting cache reader")
	}
	defer func() {
		_ = rdr.Close()
	}()
	written, err = io.Copy(dst, rdr)
	return written, err
}
