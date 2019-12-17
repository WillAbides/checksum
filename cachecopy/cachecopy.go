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

type Validator func(io.Reader) bool

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

func Copy(dst io.Writer, src io.Reader, validator func(io.Reader) bool, cache Cache) (written int64, err error) {
	if validator == nil {
		return written, fmt.Errorf("validator cannot be nil")
	}
	if cache == nil {
		cache = NewBufferCache(nil)
	}
	defer func() {
		err = cache.Close()
	}()
	_, err = io.Copy(cache, src)
	if err != nil {
		return written, fmt.Errorf("error copying to cache")
	}
	vReader, err := cache.Reader()
	if err != nil {
		return written, fmt.Errorf("error getting cache reader")
	}
	ok := validator(vReader)
	err = vReader.Close()
	if err != nil {
		return written, fmt.Errorf("error closing cache reader")
	}
	if !ok {
		return written, fmt.Errorf("src did not validate")
	}
	rdr, err := cache.Reader()
	if err != nil {
		return written, fmt.Errorf("error getting cache reader")
	}
	defer func() {
		err = rdr.Close()
	}()
	written, err = io.Copy(dst, rdr)
	return written, err
}
