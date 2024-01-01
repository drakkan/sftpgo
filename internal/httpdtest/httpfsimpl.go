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

package httpdtest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/shirou/gopsutil/v3/disk"

	"github.com/drakkan/sftpgo/v2/internal/util"
)

const (
	statPath     = "/api/v1/stat"
	openPath     = "/api/v1/open"
	createPath   = "/api/v1/create"
	renamePath   = "/api/v1/rename"
	removePath   = "/api/v1/remove"
	mkdirPath    = "/api/v1/mkdir"
	chmodPath    = "/api/v1/chmod"
	chtimesPath  = "/api/v1/chtimes"
	truncatePath = "/api/v1/truncate"
	readdirPath  = "/api/v1/readdir"
	dirsizePath  = "/api/v1/dirsize"
	mimetypePath = "/api/v1/mimetype"
	statvfsPath  = "/api/v1/statvfs"
)

// HTTPFsCallbacks defines additional callbacks to customize the HTTPfs responses
type HTTPFsCallbacks struct {
	Readdir func(string) []os.FileInfo
}

// StartTestHTTPFs starts a test HTTP service that implements httpfs
// and listens on the specified port
func StartTestHTTPFs(port int, callbacks *HTTPFsCallbacks) error {
	fs := httpFsImpl{
		port:      port,
		callbacks: callbacks,
	}

	return fs.Run()
}

// StartTestHTTPFsOverUnixSocket starts a test HTTP service that implements httpfs
// and listens on the specified UNIX domain socket path
func StartTestHTTPFsOverUnixSocket(socketPath string) error {
	fs := httpFsImpl{
		unixSocketPath: socketPath,
	}
	return fs.Run()
}

type httpFsImpl struct {
	router         *chi.Mux
	basePath       string
	port           int
	unixSocketPath string
	callbacks      *HTTPFsCallbacks
}

type apiResponse struct {
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
}

func (fs *httpFsImpl) sendAPIResponse(w http.ResponseWriter, r *http.Request, err error, message string, code int) {
	var errorString string
	if err != nil {
		errorString = err.Error()
	}
	resp := apiResponse{
		Error:   errorString,
		Message: message,
	}
	ctx := context.WithValue(r.Context(), render.StatusCtxKey, code)
	render.JSON(w, r.WithContext(ctx), resp)
}

func (fs *httpFsImpl) getUsername(r *http.Request) (string, error) {
	username, _, ok := r.BasicAuth()
	if !ok || username == "" {
		return "", os.ErrPermission
	}
	rootPath := filepath.Join(fs.basePath, username)
	_, err := os.Stat(rootPath)
	if errors.Is(err, os.ErrNotExist) {
		err = os.MkdirAll(rootPath, os.ModePerm)
		if err != nil {
			return username, err
		}
	}
	return username, nil
}

func (fs *httpFsImpl) getRespStatus(err error) int {
	if errors.Is(err, os.ErrPermission) {
		return http.StatusForbidden
	}
	if errors.Is(err, os.ErrNotExist) {
		return http.StatusNotFound
	}

	return http.StatusInternalServerError
}

func (fs *httpFsImpl) stat(w http.ResponseWriter, r *http.Request) {
	username, err := fs.getUsername(r)
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	name := getNameURLParam(r)
	fsPath := filepath.Join(fs.basePath, username, name)
	info, err := os.Stat(fsPath)
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	render.JSON(w, r, getStatFromInfo(info))
}

func (fs *httpFsImpl) open(w http.ResponseWriter, r *http.Request) {
	username, err := fs.getUsername(r)
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	var offset int64
	if r.URL.Query().Has("offset") {
		offset, err = strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
		if err != nil {
			fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
			return
		}
	}
	name := getNameURLParam(r)
	fsPath := filepath.Join(fs.basePath, username, name)
	f, err := os.Open(fsPath)
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	defer f.Close()

	if offset > 0 {
		_, err = f.Seek(offset, io.SeekStart)
		if err != nil {
			fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
			return
		}
	}
	ctype := mime.TypeByExtension(filepath.Ext(name))
	if ctype != "" {
		ctype = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ctype)
	_, err = io.Copy(w, f)
	if err != nil {
		panic(http.ErrAbortHandler)
	}
}

func (fs *httpFsImpl) create(w http.ResponseWriter, r *http.Request) {
	username, err := fs.getUsername(r)
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	flags := os.O_RDWR | os.O_CREATE | os.O_TRUNC
	if r.URL.Query().Has("flags") {
		openFlags, err := strconv.ParseInt(r.URL.Query().Get("flags"), 10, 32)
		if err != nil {
			fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
			return
		}
		if openFlags > 0 {
			flags = int(openFlags)
		}
	}
	name := getNameURLParam(r)
	fsPath := filepath.Join(fs.basePath, username, name)
	f, err := os.OpenFile(fsPath, flags, 0666)
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	defer f.Close()

	_, err = io.Copy(f, r.Body)
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	fs.sendAPIResponse(w, r, nil, "upload OK", http.StatusOK)
}

func (fs *httpFsImpl) rename(w http.ResponseWriter, r *http.Request) {
	username, err := fs.getUsername(r)
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	target := r.URL.Query().Get("target")
	if target == "" {
		fs.sendAPIResponse(w, r, nil, "target path cannot be empty", http.StatusBadRequest)
		return
	}
	name := getNameURLParam(r)
	sourcePath := filepath.Join(fs.basePath, username, name)
	targetPath := filepath.Join(fs.basePath, username, target)
	err = os.Rename(sourcePath, targetPath)
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	fs.sendAPIResponse(w, r, nil, "rename OK", http.StatusOK)
}

func (fs *httpFsImpl) remove(w http.ResponseWriter, r *http.Request) {
	username, err := fs.getUsername(r)
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	name := getNameURLParam(r)
	fsPath := filepath.Join(fs.basePath, username, name)
	err = os.Remove(fsPath)
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	fs.sendAPIResponse(w, r, nil, "remove OK", http.StatusOK)
}

func (fs *httpFsImpl) mkdir(w http.ResponseWriter, r *http.Request) {
	username, err := fs.getUsername(r)
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	name := getNameURLParam(r)
	fsPath := filepath.Join(fs.basePath, username, name)
	err = os.Mkdir(fsPath, os.ModePerm)
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	fs.sendAPIResponse(w, r, nil, "mkdir OK", http.StatusOK)
}

func (fs *httpFsImpl) chmod(w http.ResponseWriter, r *http.Request) {
	username, err := fs.getUsername(r)
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	mode, err := strconv.ParseUint(r.URL.Query().Get("mode"), 10, 32)
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	name := getNameURLParam(r)
	fsPath := filepath.Join(fs.basePath, username, name)
	err = os.Chmod(fsPath, os.FileMode(mode))
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	fs.sendAPIResponse(w, r, nil, "chmod OK", http.StatusOK)
}

func (fs *httpFsImpl) chtimes(w http.ResponseWriter, r *http.Request) {
	username, err := fs.getUsername(r)
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	atime, err := time.Parse(time.RFC3339, r.URL.Query().Get("access_time"))
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	mtime, err := time.Parse(time.RFC3339, r.URL.Query().Get("modification_time"))
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	name := getNameURLParam(r)
	fsPath := filepath.Join(fs.basePath, username, name)
	err = os.Chtimes(fsPath, atime, mtime)
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	fs.sendAPIResponse(w, r, nil, "chtimes OK", http.StatusOK)
}

func (fs *httpFsImpl) truncate(w http.ResponseWriter, r *http.Request) {
	username, err := fs.getUsername(r)
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	size, err := strconv.ParseInt(r.URL.Query().Get("size"), 10, 64)
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	name := getNameURLParam(r)
	fsPath := filepath.Join(fs.basePath, username, name)
	err = os.Truncate(fsPath, size)
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	fs.sendAPIResponse(w, r, nil, "chmod OK", http.StatusOK)
}

func (fs *httpFsImpl) readdir(w http.ResponseWriter, r *http.Request) {
	username, err := fs.getUsername(r)
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	name := getNameURLParam(r)
	fsPath := filepath.Join(fs.basePath, username, name)
	f, err := os.Open(fsPath)
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	list, err := f.Readdir(-1)
	f.Close()
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	result := make([]map[string]any, 0, len(list))
	for _, fi := range list {
		result = append(result, getStatFromInfo(fi))
	}
	if fs.callbacks != nil && fs.callbacks.Readdir != nil {
		for _, fi := range fs.callbacks.Readdir(name) {
			result = append(result, getStatFromInfo(fi))
		}
	}
	render.JSON(w, r, result)
}

func (fs *httpFsImpl) dirsize(w http.ResponseWriter, r *http.Request) {
	username, err := fs.getUsername(r)
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	name := getNameURLParam(r)
	fsPath := filepath.Join(fs.basePath, username, name)
	info, err := os.Stat(fsPath)
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	numFiles := 0
	size := int64(0)
	if info.IsDir() {
		err = filepath.Walk(fsPath, func(_ string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info != nil && info.Mode().IsRegular() {
				size += info.Size()
				numFiles++
			}
			return err
		})
		if err != nil {
			fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
			return
		}
	}
	render.JSON(w, r, map[string]any{
		"files": numFiles,
		"size":  size,
	})
}

func (fs *httpFsImpl) mimetype(w http.ResponseWriter, r *http.Request) {
	username, err := fs.getUsername(r)
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	name := getNameURLParam(r)
	fsPath := filepath.Join(fs.basePath, username, name)
	f, err := os.OpenFile(fsPath, os.O_RDONLY, 0)
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	defer f.Close()
	var buf [512]byte
	n, err := io.ReadFull(f, buf[:])
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	ctype := http.DetectContentType(buf[:n])
	render.JSON(w, r, map[string]any{
		"mime": ctype,
	})
}

func (fs *httpFsImpl) statvfs(w http.ResponseWriter, r *http.Request) {
	username, err := fs.getUsername(r)
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	name := getNameURLParam(r)
	fsPath := filepath.Join(fs.basePath, username, name)
	usage, err := disk.Usage(fsPath)
	if err != nil {
		fs.sendAPIResponse(w, r, err, "", fs.getRespStatus(err))
		return
	}
	// we assume block size = 4096
	bsize := uint64(4096)
	blocks := usage.Total / bsize
	bfree := usage.Free / bsize
	files := usage.InodesTotal
	ffree := usage.InodesFree
	if files == 0 {
		// these assumptions are wrong but still better than returning 0
		files = blocks / 4
		ffree = bfree / 4
	}
	render.JSON(w, r, map[string]any{
		"bsize":   bsize,
		"frsize":  bsize,
		"blocks":  blocks,
		"bfree":   bfree,
		"bavail":  bfree,
		"files":   files,
		"ffree":   ffree,
		"favail":  ffree,
		"namemax": 255,
	})
}

func (fs *httpFsImpl) configureRouter() {
	fs.router = chi.NewRouter()
	fs.router.Use(middleware.Recoverer)

	fs.router.Get(statPath+"/{name}", fs.stat) //nolint:goconst
	fs.router.Get(openPath+"/{name}", fs.open)
	fs.router.Post(createPath+"/{name}", fs.create)
	fs.router.Patch(renamePath+"/{name}", fs.rename)
	fs.router.Delete(removePath+"/{name}", fs.remove)
	fs.router.Post(mkdirPath+"/{name}", fs.mkdir)
	fs.router.Patch(chmodPath+"/{name}", fs.chmod)
	fs.router.Patch(chtimesPath+"/{name}", fs.chtimes)
	fs.router.Patch(truncatePath+"/{name}", fs.truncate)
	fs.router.Get(readdirPath+"/{name}", fs.readdir)
	fs.router.Get(dirsizePath+"/{name}", fs.dirsize)
	fs.router.Get(mimetypePath+"/{name}", fs.mimetype)
	fs.router.Get(statvfsPath+"/{name}", fs.statvfs)
}

func (fs *httpFsImpl) Run() error {
	fs.basePath = filepath.Join(os.TempDir(), "httpfs")
	if err := os.RemoveAll(fs.basePath); err != nil {
		return err
	}
	if err := os.MkdirAll(fs.basePath, os.ModePerm); err != nil {
		return err
	}
	fs.configureRouter()

	httpServer := http.Server{
		Addr:           fmt.Sprintf(":%d", fs.port),
		Handler:        fs.router,
		ReadTimeout:    60 * time.Second,
		WriteTimeout:   60 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 16, // 64KB
	}

	if fs.unixSocketPath == "" {
		return httpServer.ListenAndServe()
	}
	err := os.Remove(fs.unixSocketPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	listener, err := net.Listen("unix", fs.unixSocketPath)
	if err != nil {
		return err
	}
	return httpServer.Serve(listener)
}

func getStatFromInfo(info os.FileInfo) map[string]any {
	return map[string]any{
		"name":          info.Name(),
		"size":          info.Size(),
		"mode":          info.Mode(),
		"last_modified": info.ModTime(),
	}
}

func getNameURLParam(r *http.Request) string {
	v := chi.URLParam(r, "name")
	unescaped, err := url.PathUnescape(v)
	if err != nil {
		return util.CleanPath(v)
	}
	return util.CleanPath(unescaped)
}
