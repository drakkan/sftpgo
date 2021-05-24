package sftpd

import (
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"

	"github.com/drakkan/sftpgo/vfs"
)

type PrefixMatch uint8

const (
	PathContainsPrefix PrefixMatch = iota
	PathIsPrefixParent
	PathDiverged

	methodList = `List`
	methodStat = `Stat`
)

type Middleware interface {
	sftp.OpenFileWriter
	sftp.LstatFileLister
	sftp.FileWriter
	sftp.FileCmder
	sftp.FileReader
	sftp.FileLister
	sftp.StatVFSFileCmder
}

var _ Middleware = &prefixMiddleware{}
var _ Middleware = &Connection{}

type prefixMiddleware struct {
	prefix string
	next   Middleware
}

func (p *prefixMiddleware) Lstat(request *sftp.Request) (sftp.ListerAt, error) {
	switch GetPrefixHierarchy(p.prefix, request.Filepath) {
	case PathContainsPrefix:
		request.Filepath, _ = p.removeFolderPrefix(request.Filepath)
		return p.next.Lstat(request)
	case PathIsPrefixParent:
		return listerAt([]os.FileInfo{
			vfs.NewFileInfo(request.Filepath, true, 0, time.Now(), false),
		}), nil
	default:
		return nil, sftp.ErrSSHFxPermissionDenied
	}
}

func (p *prefixMiddleware) OpenFile(request *sftp.Request) (sftp.WriterAtReaderAt, error) {
	switch GetPrefixHierarchy(p.prefix, request.Filepath) {
	case PathContainsPrefix:
		request.Filepath, _ = p.removeFolderPrefix(request.Filepath)
		return p.next.OpenFile(request)
	default:
		return nil, sftp.ErrSSHFxPermissionDenied
	}
}

func (p *prefixMiddleware) Filelist(request *sftp.Request) (sftp.ListerAt, error) {
	switch GetPrefixHierarchy(p.prefix, request.Filepath) {
	case PathContainsPrefix:
		request.Filepath, _ = p.removeFolderPrefix(request.Filepath)
		return p.next.Filelist(request)
	case PathIsPrefixParent:
		Now := time.Now()
		switch request.Method {
		case methodList:
			FileName := p.nextListFolder(request.Filepath)
			return listerAt([]os.FileInfo{
				// vfs.NewFileInfo(`.`, true, 0, Now, false),
				vfs.NewFileInfo(FileName, true, 0, Now, false),
			}), nil
		case methodStat:
			return listerAt([]os.FileInfo{
				vfs.NewFileInfo(request.Filepath, true, 0, Now, false),
			}), nil
		default:
			return nil, sftp.ErrSSHFxOpUnsupported
		}
	default:
		return nil, sftp.ErrSSHFxPermissionDenied
	}
}

func (p *prefixMiddleware) Filewrite(request *sftp.Request) (io.WriterAt, error) {
	switch GetPrefixHierarchy(p.prefix, request.Filepath) {
	case PathContainsPrefix:
		// forward to next handler
		request.Filepath, _ = p.removeFolderPrefix(request.Filepath)
		return p.next.Filewrite(request)
	default:
		return nil, sftp.ErrSSHFxPermissionDenied
	}
}

func (p *prefixMiddleware) Fileread(request *sftp.Request) (io.ReaderAt, error) {
	switch GetPrefixHierarchy(p.prefix, request.Filepath) {
	case PathContainsPrefix:
		request.Filepath, _ = p.removeFolderPrefix(request.Filepath)
		return p.next.Fileread(request)
	default:
		return nil, sftp.ErrSSHFxPermissionDenied
	}
}

func (p *prefixMiddleware) Filecmd(request *sftp.Request) error {
	switch request.Method {
	case "Rename", "Symlink":
		if GetPrefixHierarchy(p.prefix, request.Filepath) == PathContainsPrefix &&
			GetPrefixHierarchy(p.prefix, request.Target) == PathContainsPrefix {
			request.Filepath, _ = p.removeFolderPrefix(request.Filepath)
			request.Target, _ = p.removeFolderPrefix(request.Target)
			return p.next.Filecmd(request)
		}
		return sftp.ErrSSHFxPermissionDenied
	// commands have a source and destination (file path and target path)
	case "Setstat", "Rmdir", "Mkdir", "Remove":
		// commands just the file path
		if GetPrefixHierarchy(p.prefix, request.Filepath) == PathContainsPrefix {
			request.Filepath, _ = p.removeFolderPrefix(request.Filepath)
			return p.next.Filecmd(request)
		}
		return sftp.ErrSSHFxPermissionDenied
	default:
		return sftp.ErrSSHFxOpUnsupported
	}
}

func (p *prefixMiddleware) StatVFS(request *sftp.Request) (*sftp.StatVFS, error) {
	switch GetPrefixHierarchy(p.prefix, request.Filepath) {
	case PathContainsPrefix:
		// forward to next handler
		request.Filepath, _ = p.removeFolderPrefix(request.Filepath)
		return p.next.StatVFS(request)
	default:
		return nil, sftp.ErrSSHFxPermissionDenied
	}
}

func (p *prefixMiddleware) nextListFolder(requestPath string) string {
	cleanPath := filepath.Clean(`/` + requestPath)
	cleanPrefix := filepath.Clean(`/` + p.prefix)

	FileName := cleanPrefix[len(cleanPath):]
	FileName = strings.TrimLeft(FileName, `/`)
	SlashIndex := strings.Index(FileName, `/`)
	if SlashIndex > 0 {
		return FileName[0:SlashIndex]
	}
	return FileName
}

func NewPrefixMiddleware(prefix string, next Middleware) Middleware {
	return &prefixMiddleware{
		prefix: prefix,
		next:   next,
	}
}

func (p *prefixMiddleware) containsPrefix(virtualPath string) bool {
	if !path.IsAbs(virtualPath) {
		virtualPath = path.Clean(`/` + virtualPath)
	}

	if p.prefix == `/` || p.prefix == `` {
		return true
	} else if p.prefix == virtualPath {
		return true
	}

	return strings.HasPrefix(virtualPath, p.prefix+`/`)
}

func (p *prefixMiddleware) removeFolderPrefix(virtualPath string) (string, bool) {
	if p.prefix == `/` || p.prefix == `` {
		return virtualPath, true
	}

	virtualPath = filepath.Clean(`/` + virtualPath)
	if p.containsPrefix(virtualPath) {
		effectivePath := virtualPath[len(p.prefix):]
		if effectivePath == `` {
			effectivePath = `/`
		}
		return effectivePath, true
	}
	return virtualPath, false
}

func GetPrefixHierarchy(prefix, path string) PrefixMatch {
	prefixSplit := strings.Split(filepath.Clean(`/`+prefix), `/`)
	pathSplit := strings.Split(filepath.Clean(`/`+path), `/`)

	for {
		// stop if either slice is empty of the current head elements do not match
		if len(prefixSplit) == 0 || len(pathSplit) == 0 ||
			prefixSplit[0] != pathSplit[0] {
			break
		}
		prefixSplit = prefixSplit[1:]
		pathSplit = pathSplit[1:]
	}

	// The entire Prefix is included in Test Path
	// Example: Prefix (/files) with Test Path (/files/test.csv)
	if len(prefixSplit) == 0 ||
		(len(prefixSplit) == 1 && prefixSplit[0] == ``) {
		return PathContainsPrefix
	}

	// Test Path is part of the Prefix Hierarchy
	// Example: Prefix (/files) with Test Path (/)
	if len(pathSplit) == 0 ||
		(len(pathSplit) == 1 && pathSplit[0] == ``) {
		return PathIsPrefixParent
	}

	// Test Path is not with the Prefix Hierarchy
	// Example: Prefix (/files) with Test Path (/files2)
	return PathDiverged
}
