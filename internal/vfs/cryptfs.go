// Copyright (C) 2019 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package vfs

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/eikenb/pipeat"
	"github.com/minio/sio"
	"golang.org/x/crypto/hkdf"

	"github.com/drakkan/sftpgo/v2/internal/logger"
)

const (
	// cryptFsName is the name for the local Fs implementation with encryption support
	cryptFsName         = "cryptfs"
	version10     byte  = 0x10
	nonceV10Size  int   = 32
	headerV10Size int64 = 33 // 1 (version byte) + 32 (nonce size)
)

// CryptFs is a Fs implementation that allows to encrypts/decrypts local files
type CryptFs struct {
	*OsFs
	localTempDir string
	masterKey    []byte
}

// NewCryptFs returns a CryptFs object
func NewCryptFs(connectionID, rootDir, mountPath string, config CryptFsConfig) (Fs, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	if err := config.Passphrase.TryDecrypt(); err != nil {
		return nil, err
	}
	fs := &CryptFs{
		OsFs: &OsFs{
			name:            cryptFsName,
			connectionID:    connectionID,
			rootDir:         rootDir,
			mountPath:       getMountPath(mountPath),
			readBufferSize:  config.OSFsConfig.ReadBufferSize * 1024 * 1024,
			writeBufferSize: config.OSFsConfig.WriteBufferSize * 1024 * 1024,
		},
		masterKey: []byte(config.Passphrase.GetPayload()),
	}
	if tempPath == "" {
		fs.localTempDir = rootDir
	} else {
		fs.localTempDir = tempPath
	}
	return fs, nil
}

// Name returns the name for the Fs implementation
func (fs *CryptFs) Name() string {
	return fs.name
}

// Open opens the named file for reading
func (fs *CryptFs) Open(name string, offset int64) (File, PipeReader, func(), error) {
	f, key, err := fs.getFileAndEncryptionKey(name)
	if err != nil {
		return nil, nil, nil, err
	}
	isZeroDownload, err := isZeroBytesDownload(f, offset)
	if err != nil {
		f.Close()
		return nil, nil, nil, err
	}
	r, w, err := pipeat.PipeInDir(fs.localTempDir)
	if err != nil {
		f.Close()
		return nil, nil, nil, err
	}
	p := NewPipeReader(r)

	go func() {
		if isZeroDownload {
			w.CloseWithError(err) //nolint:errcheck
			f.Close()
			fsLog(fs, logger.LevelDebug, "zero bytes download completed, path: %q", name)
			return
		}
		var n int64
		var err error

		if offset == 0 {
			n, err = fs.decryptWrapper(w, f, fs.getSIOConfig(key))
		} else {
			var readerAt io.ReaderAt
			var readed, written int
			buf := make([]byte, 65568)
			wrapper := &cryptedFileWrapper{
				File: f,
			}
			readerAt, err = sio.DecryptReaderAt(wrapper, fs.getSIOConfig(key))
			if err == nil {
				finished := false
				for !finished {
					readed, err = readerAt.ReadAt(buf, offset)
					offset += int64(readed)
					if err != nil && err != io.EOF {
						break
					}
					if err == io.EOF {
						finished = true
						err = nil
					}
					if readed > 0 {
						written, err = w.Write(buf[:readed])
						n += int64(written)
						if err != nil {
							if err == io.EOF {
								err = io.ErrUnexpectedEOF
							}
							break
						}
						if readed != written {
							err = io.ErrShortWrite
							break
						}
					}
				}
			}
		}
		w.CloseWithError(err) //nolint:errcheck
		f.Close()
		fsLog(fs, logger.LevelDebug, "download completed, path: %q size: %v, err: %v", name, n, err)
	}()

	return nil, p, nil, nil
}

// Create creates or opens the named file for writing
func (fs *CryptFs) Create(name string, _, _ int) (File, PipeWriter, func(), error) {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return nil, nil, nil, err
	}
	header := encryptedFileHeader{
		version: version10,
		nonce:   make([]byte, 32),
	}
	_, err = io.ReadFull(rand.Reader, header.nonce)
	if err != nil {
		f.Close()
		return nil, nil, nil, err
	}
	var key [32]byte
	kdf := hkdf.New(sha256.New, fs.masterKey, header.nonce, nil)
	_, err = io.ReadFull(kdf, key[:])
	if err != nil {
		f.Close()
		return nil, nil, nil, err
	}
	r, w, err := pipeat.PipeInDir(fs.localTempDir)
	if err != nil {
		f.Close()
		return nil, nil, nil, err
	}
	err = header.Store(f)
	if err != nil {
		r.Close()
		w.Close()
		f.Close()
		return nil, nil, nil, err
	}
	p := NewPipeWriter(w)

	go func() {
		var n int64
		var err error
		if fs.writeBufferSize <= 0 {
			n, err = sio.Encrypt(f, r, fs.getSIOConfig(key))
		} else {
			bw := bufio.NewWriterSize(f, fs.writeBufferSize)
			n, err = fs.encryptWrapper(bw, r, fs.getSIOConfig(key))
			errFlush := bw.Flush()
			if err == nil && errFlush != nil {
				err = errFlush
			}
		}
		errClose := f.Close()
		if err == nil && errClose != nil {
			err = errClose
		}
		r.CloseWithError(err) //nolint:errcheck
		p.Done(err)
		fsLog(fs, logger.LevelDebug, "upload completed, path: %q, readed bytes: %v, err: %v", name, n, err)
	}()

	return nil, p, nil, nil
}

// Truncate changes the size of the named file
func (*CryptFs) Truncate(_ string, _ int64) error {
	return ErrVfsUnsupported
}

// ReadDir reads the directory named by dirname and returns
// a list of directory entries.
func (fs *CryptFs) ReadDir(dirname string) (DirLister, error) {
	f, err := os.Open(dirname)
	if err != nil {
		if isInvalidNameError(err) {
			err = os.ErrNotExist
		}
		return nil, err
	}

	return &cryptFsDirLister{f}, nil
}

// IsUploadResumeSupported returns false sio does not support random access writes
func (*CryptFs) IsUploadResumeSupported() bool {
	return false
}

// IsConditionalUploadResumeSupported returns if resuming uploads is supported
// for the specified size
func (*CryptFs) IsConditionalUploadResumeSupported(_ int64) bool {
	return false
}

// GetMimeType returns the content type
func (fs *CryptFs) GetMimeType(name string) (string, error) {
	f, key, err := fs.getFileAndEncryptionKey(name)
	if err != nil {
		return "", err
	}
	defer f.Close()

	readSize, err := sio.DecryptedSize(512)
	if err != nil {
		return "", err
	}
	buf := make([]byte, readSize)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return "", err
	}

	decrypted := bytes.NewBuffer(nil)
	_, err = sio.Decrypt(decrypted, bytes.NewBuffer(buf[:n]), fs.getSIOConfig(key))
	if err != nil {
		return "", err
	}

	ctype := http.DetectContentType(decrypted.Bytes())
	// Rewind file.
	_, err = f.Seek(0, io.SeekStart)
	return ctype, err
}

func (fs *CryptFs) getSIOConfig(key [32]byte) sio.Config {
	return sio.Config{
		MinVersion: sio.Version20,
		MaxVersion: sio.Version20,
		Key:        key[:],
	}
}

// ConvertFileInfo returns a FileInfo with the decrypted size
func (fs *CryptFs) ConvertFileInfo(info os.FileInfo) os.FileInfo {
	return convertCryptFsInfo(info)
}

func (fs *CryptFs) getFileAndEncryptionKey(name string) (*os.File, [32]byte, error) {
	var key [32]byte
	f, err := os.Open(name)
	if err != nil {
		return nil, key, err
	}
	header := encryptedFileHeader{}
	err = header.Load(f)
	if err != nil {
		f.Close()
		return nil, key, err
	}
	kdf := hkdf.New(sha256.New, fs.masterKey, header.nonce, nil)
	_, err = io.ReadFull(kdf, key[:])
	if err != nil {
		f.Close()
		return nil, key, err
	}
	return f, key, err
}

func (*CryptFs) encryptWrapper(dst io.Writer, src io.Reader, config sio.Config) (int64, error) {
	encReader, err := sio.EncryptReader(src, config)
	if err != nil {
		return 0, err
	}
	return doCopy(dst, encReader, make([]byte, 65568))
}

func (fs *CryptFs) decryptWrapper(dst io.Writer, src io.Reader, config sio.Config) (int64, error) {
	if fs.readBufferSize <= 0 {
		return sio.Decrypt(dst, src, config)
	}
	br := bufio.NewReaderSize(src, fs.readBufferSize)
	decReader, err := sio.DecryptReader(br, config)
	if err != nil {
		return 0, err
	}
	return doCopy(dst, decReader, make([]byte, 65568))
}

func isZeroBytesDownload(f *os.File, offset int64) (bool, error) {
	info, err := f.Stat()
	if err != nil {
		return false, err
	}
	if info.Size() == headerV10Size {
		return true, nil
	}
	if info.Size() > headerV10Size {
		decSize, err := sio.DecryptedSize(uint64(info.Size() - headerV10Size))
		if err != nil {
			return false, err
		}
		if int64(decSize) == offset {
			return true, nil
		}
	}
	return false, nil
}

func convertCryptFsInfo(info os.FileInfo) os.FileInfo {
	if !info.Mode().IsRegular() {
		return info
	}
	size := info.Size()
	if size >= headerV10Size {
		size -= headerV10Size
		decryptedSize, err := sio.DecryptedSize(uint64(size))
		if err == nil {
			size = int64(decryptedSize)
		}
	} else {
		size = 0
	}
	return NewFileInfo(info.Name(), info.IsDir(), size, info.ModTime(), false)
}

type encryptedFileHeader struct {
	version byte
	nonce   []byte
}

func (h *encryptedFileHeader) Store(f *os.File) error {
	buf := make([]byte, 0, headerV10Size)
	buf = append(buf, version10)
	buf = append(buf, h.nonce...)
	_, err := f.Write(buf)
	return err
}

func (h *encryptedFileHeader) Load(f *os.File) error {
	header := make([]byte, 1+nonceV10Size)
	_, err := io.ReadFull(f, header)
	if err != nil {
		return err
	}
	h.version = header[0]
	if h.version == version10 {
		h.nonce = header[1:]
		return nil
	}
	return fmt.Errorf("unsupported encryption version: %v", h.version)
}

type cryptedFileWrapper struct {
	*os.File
}

func (w *cryptedFileWrapper) ReadAt(p []byte, offset int64) (n int, err error) {
	return w.File.ReadAt(p, offset+headerV10Size)
}

type cryptFsDirLister struct {
	f *os.File
}

func (l *cryptFsDirLister) Next(limit int) ([]os.FileInfo, error) {
	if limit <= 0 {
		return nil, errInvalidDirListerLimit
	}
	files, err := l.f.Readdir(limit)
	for idx := range files {
		files[idx] = convertCryptFsInfo(files[idx])
	}
	return files, err
}

func (l *cryptFsDirLister) Close() error {
	return l.f.Close()
}
