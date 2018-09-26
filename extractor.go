// Packages extractor provides a way to recursively extract or decompress
// archives, resuling in a "stream" of readers that can be used sequentially.

package extractor

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/bzip2"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/nwaples/rardecode"
	"github.com/pierrec/lz4"
	"github.com/ulikunitz/xz"

	"github.com/aerissecure/mime"
)

var NestError = errors.New("reader is nested archive that cannot be extracted.")

type extractor struct {
	r        io.Reader // underlying io.reader
	c        chan *filestream
	filename string
	once     sync.Once
	sep      string // filename separator for nested files
}

// New configures and returns an extractor.
func New(r io.Reader, filename string) *extractor {
	c := make(chan *filestream)
	return &extractor{
		r:        r,
		filename: filename,
		c:        c,
		sep:      ":",
	}
}

type filestream struct {
	r        io.Reader
	filename string
	err      error
}

// extract recursively extracts bufio.Readers and writes them to extractor.c
// channel using the io.Reader passed in with the first filestream.
// Note, filestream uses io.Reader for flexibility in calling extract, but
// all filestreams written to extractor.c channel are type bufio.Reader.
func (e *extractor) extract(f *filestream) {
	// ensure all branches guarantee a write to e.c, otherwise it will deadlock.

	br, ok := f.r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(f.r)
	}

	buf, _ := br.Peek(512)
	mtype := mime.Detect(buf)

	if mtype == mime.Gzip {
		r, err := gzip.NewReader(br)
		if err != nil {
			f.err = err
			f.r = br
			e.c <- f
			return
		}

		// is this close in the right spot, or do we need to pass require the caller to call close?
		defer r.Close()
		fname := f.filename + e.sep + r.Name
		e.extract(&filestream{r: r, filename: fname})
		return
	}

	if mtype == mime.Bzip2 {
		r := bzip2.NewReader(br)
		// compression only, get name by removing file extension
		fname := f.filename
		split := strings.Split(f.filename, e.sep)
		base := split[len(split)-1]
		ext := filepath.Ext(base)
		if ext == ".bz2" {
			fname = f.filename + e.sep + base[:len(base)-len(ext)]
		}
		e.extract(&filestream{r: r, filename: fname})
		return
	}

	if mtype == mime.Zip {
		// only process if is os.File. If caller wants the reader anyway, use
		// NextWithError and check if err == NestError, along with the mime type.

		of, ok := f.r.(*os.File)
		if !ok {
			f.err = NestError
			f.r = br
			e.c <- f
			return
		}
		fi, err := of.Stat()
		if err != nil {
			f.err = err
			f.r = br
			e.c <- f
			return
		}
		r, err := zip.NewReader(of, fi.Size())
		if err != nil {
			f.err = err
			f.r = br
			e.c <- f
			return
		}
		for _, file := range r.File {
			zfr, err := file.Open()
			if err != nil {
				e.c <- &filestream{r: bufio.NewReader(zfr), err: err}
				continue
			}
			fname := f.filename + e.sep + file.Name
			e.extract(&filestream{r: zfr, filename: fname})
		}
		return
	}

	if mtype == mime.Tar {
		r := tar.NewReader(br)
		for {
			hdr, err := r.Next()
			if err == io.EOF { // include io.EOF
				e.c <- &filestream{r: bufio.NewReader(r), err: err}
				return
			}
			if hdr.Typeflag != tar.TypeReg {
				// don't write to e.c
				continue
			}
			fname := f.filename + e.sep + hdr.Name
			e.extract(&filestream{r: r, filename: fname})
		}
		return // make sure to return a the end of each case
	}

	if mtype == mime.Rar {
		r, err := rardecode.NewReader(br, "")
		if err != nil {
			f.err = err
			f.r = br
			e.c <- f
			return
		}
		for {
			hdr, err := r.Next()
			if err != nil { // includes io.EOF
				e.c <- &filestream{r: bufio.NewReader(r), err: err}
				return
			}
			if hdr.IsDir {
				// don't write to e.c
				continue
			}
			fmt.Println("name:", hdr.Name)
			fname := f.filename + e.sep + hdr.Name
			e.extract(&filestream{r: r, filename: fname})
		}
		return // make sure to return a the end of each case
	}

	if mtype == mime.Xz {
		r, err := xz.NewReader(br)
		if err != nil {
			f.err = err
			f.r = br
			e.c <- f
			return
		}

		// compression only, get name by removing file extension
		fname := f.filename
		split := strings.Split(f.filename, e.sep)
		base := split[len(split)-1]
		ext := filepath.Ext(base)
		if ext == ".xz" {
			fname = f.filename + e.sep + base[:len(base)-len(ext)]
		}
		e.extract(&filestream{r: r, filename: fname})
		return
	}

	if mtype == mime.Lz4 {
		r := lz4.NewReader(br)

		// compression only, get name by removing file extension
		fname := f.filename
		split := strings.Split(f.filename, e.sep)
		base := split[len(split)-1]
		ext := filepath.Ext(base)
		if ext == ".lz4" {
			fname = f.filename + e.sep + base[:len(base)-len(ext)]
		}
		e.extract(&filestream{r: r, filename: fname})
		return
	}

	// if mtype == mime.Sz {}

	// not a nested archive, send the input filestream out the channel, with
	// reader as bufio.Reader
	f.r = br
	e.c <- f
	return
}

// Next retreives the next reader nested in the reader configured on the
// extractor instance. If more is false, then the returned reader is nil
// and should not be used. If more is true, then the reader and filename
// are valid and ready to be used. The returned reader is only safe to use
// until Next is called again.
func (e *extractor) Next() (r *bufio.Reader, filename string, more bool) {
	e.once.Do(func() {
		go func() {
			e.extract(&filestream{r: e.r, filename: e.filename})
			close(e.c)
		}()
	})

	for {
		fs, more := <-e.c
		if !more {
			return r, filename, more
		}
		if fs.err != nil {
			continue
		}
		return fs.r.(*bufio.Reader), fs.filename, more
	}
}

// NextWithError is similar to Next only all encountered readers are returned
// whether they are valid or not. Generally, if err != nil, the reader should
// not be used, though its value will not be nil. However, if err == NestError,
// the reader can be used but it represents a nested archive that cannot be
// extracted and is most likely useless to the caller.
func (e *extractor) NextWithError() (r *bufio.Reader, filename string, err error, more bool) {
	e.once.Do(func() {
		go func() {
			e.extract(&filestream{r: e.r, filename: e.filename})
			close(e.c)
		}()
	})

	fs, more := <-e.c
	if !more {
		// fs==nil if !more
		return r, filename, err, more
	}
	return fs.r.(*bufio.Reader), fs.filename, fs.err, more
}
