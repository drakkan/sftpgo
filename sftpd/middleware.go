package sftpd

import (
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/pkg/sftp"

	"github.com/drakkan/sftpgo/v2/vfs"
)

// Middleware defines the interface for SFTP middlewares
type Middleware interface {
	sftp.FileReader
	sftp.FileWriter
	sftp.OpenFileWriter
	sftp.FileCmder
	sftp.StatVFSFileCmder
	sftp.FileLister
	sftp.LstatFileLister
}

type prefixMatch uint8

const (
	pathContainsPrefix prefixMatch = iota
	pathIsPrefixParent
	pathDiverged

	methodList = "List"
	methodStat = "Stat"
)

type prefixMiddleware struct {
	prefix string
	next   Middleware
}

func newPrefixMiddleware(prefix string, next Middleware) Middleware {
	return &prefixMiddleware{
		prefix: prefix,
		next:   next,
	}
}

func (p *prefixMiddleware) Lstat(request *sftp.Request) (sftp.ListerAt, error) {
	switch getPrefixHierarchy(p.prefix, request.Filepath) {
	case pathContainsPrefix:
		request.Filepath, _ = p.removeFolderPrefix(request.Filepath)
		return p.next.Lstat(request)
	case pathIsPrefixParent:
		return listerAt([]os.FileInfo{
			vfs.NewFileInfo(request.Filepath, true, 0, time.Now(), false),
		}), nil
	default:
		return nil, sftp.ErrSSHFxPermissionDenied
	}
}

func (p *prefixMiddleware) OpenFile(request *sftp.Request) (sftp.WriterAtReaderAt, error) {
	switch getPrefixHierarchy(p.prefix, request.Filepath) {
	case pathContainsPrefix:
		request.Filepath, _ = p.removeFolderPrefix(request.Filepath)
		return p.next.OpenFile(request)
	default:
		return nil, sftp.ErrSSHFxPermissionDenied
	}
}

func (p *prefixMiddleware) Filelist(request *sftp.Request) (sftp.ListerAt, error) {
	switch getPrefixHierarchy(p.prefix, request.Filepath) {
	case pathContainsPrefix:
		request.Filepath, _ = p.removeFolderPrefix(request.Filepath)
		return p.next.Filelist(request)
	case pathIsPrefixParent:
		switch request.Method {
		case methodList:
			now := time.Now()
			fileName := p.nextListFolder(request.Filepath)
			files := make([]os.FileInfo, 0, 3)
			files = append(files, vfs.NewFileInfo(".", true, 0, now, false))
			if request.Filepath != "/" {
				files = append(files, vfs.NewFileInfo("..", true, 0, now, false))
			}
			files = append(files, vfs.NewFileInfo(fileName, true, 0, now, false))
			return listerAt(files), nil
		case methodStat:
			return listerAt([]os.FileInfo{
				vfs.NewFileInfo(request.Filepath, true, 0, time.Now(), false),
			}), nil
		default:
			return nil, sftp.ErrSSHFxOpUnsupported
		}
	default:
		return nil, sftp.ErrSSHFxPermissionDenied
	}
}

func (p *prefixMiddleware) Filewrite(request *sftp.Request) (io.WriterAt, error) {
	switch getPrefixHierarchy(p.prefix, request.Filepath) {
	case pathContainsPrefix:
		// forward to next handler
		request.Filepath, _ = p.removeFolderPrefix(request.Filepath)
		return p.next.Filewrite(request)
	default:
		return nil, sftp.ErrSSHFxPermissionDenied
	}
}

func (p *prefixMiddleware) Fileread(request *sftp.Request) (io.ReaderAt, error) {
	switch getPrefixHierarchy(p.prefix, request.Filepath) {
	case pathContainsPrefix:
		request.Filepath, _ = p.removeFolderPrefix(request.Filepath)
		return p.next.Fileread(request)
	default:
		return nil, sftp.ErrSSHFxPermissionDenied
	}
}

func (p *prefixMiddleware) Filecmd(request *sftp.Request) error {
	switch request.Method {
	case "Rename", "Symlink":
		if getPrefixHierarchy(p.prefix, request.Filepath) == pathContainsPrefix &&
			getPrefixHierarchy(p.prefix, request.Target) == pathContainsPrefix {
			request.Filepath, _ = p.removeFolderPrefix(request.Filepath)
			request.Target, _ = p.removeFolderPrefix(request.Target)
			return p.next.Filecmd(request)
		}
		return sftp.ErrSSHFxPermissionDenied
	// commands have a source and destination (file path and target path)
	case "Setstat", "Rmdir", "Mkdir", "Remove":
		// commands just the file path
		if getPrefixHierarchy(p.prefix, request.Filepath) == pathContainsPrefix {
			request.Filepath, _ = p.removeFolderPrefix(request.Filepath)
			return p.next.Filecmd(request)
		}
		return sftp.ErrSSHFxPermissionDenied
	default:
		return sftp.ErrSSHFxOpUnsupported
	}
}

func (p *prefixMiddleware) StatVFS(request *sftp.Request) (*sftp.StatVFS, error) {
	switch getPrefixHierarchy(p.prefix, request.Filepath) {
	case pathContainsPrefix:
		// forward to next handler
		request.Filepath, _ = p.removeFolderPrefix(request.Filepath)
		return p.next.StatVFS(request)
	default:
		return nil, sftp.ErrSSHFxPermissionDenied
	}
}

func (p *prefixMiddleware) nextListFolder(requestPath string) string {
	cleanPath := path.Clean(`/` + requestPath)
	cleanPrefix := path.Clean(`/` + p.prefix)

	fileName := cleanPrefix[len(cleanPath):]
	fileName = strings.TrimLeft(fileName, `/`)
	slashIndex := strings.Index(fileName, `/`)
	if slashIndex > 0 {
		return fileName[0:slashIndex]
	}
	return fileName
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

	virtualPath = path.Clean(`/` + virtualPath)
	if p.containsPrefix(virtualPath) {
		effectivePath := virtualPath[len(p.prefix):]
		if effectivePath == `` {
			effectivePath = `/`
		}
		return effectivePath, true
	}
	return virtualPath, false
}

func getPrefixHierarchy(prefix, virtualPath string) prefixMatch {
	prefixSplit := strings.Split(path.Clean(`/`+prefix), `/`)
	pathSplit := strings.Split(path.Clean(`/`+virtualPath), `/`)

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
		return pathContainsPrefix
	}

	// Test Path is part of the Prefix Hierarchy
	// Example: Prefix (/files) with Test Path (/)
	if len(pathSplit) == 0 ||
		(len(pathSplit) == 1 && pathSplit[0] == ``) {
		return pathIsPrefixParent
	}

	// Test Path is not with the Prefix Hierarchy
	// Example: Prefix (/files) with Test Path (/files2)
	return pathDiverged
}
