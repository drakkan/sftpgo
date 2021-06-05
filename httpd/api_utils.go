package httpd

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/go-chi/render"
	"github.com/klauspost/compress/zip"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/vfs"
)

func sendAPIResponse(w http.ResponseWriter, r *http.Request, err error, message string, code int) {
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

func getRespStatus(err error) int {
	if _, ok := err.(*vfs.ValidationError); ok {
		return http.StatusBadRequest
	}
	if _, ok := err.(*dataprovider.MethodDisabledError); ok {
		return http.StatusForbidden
	}
	if _, ok := err.(*dataprovider.RecordNotFoundError); ok {
		return http.StatusNotFound
	}
	if os.IsNotExist(err) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func handleCloseConnection(w http.ResponseWriter, r *http.Request) {
	connectionID := getURLParam(r, "connectionID")
	if connectionID == "" {
		sendAPIResponse(w, r, nil, "connectionID is mandatory", http.StatusBadRequest)
		return
	}
	if common.Connections.Close(connectionID) {
		sendAPIResponse(w, r, nil, "Connection closed", http.StatusOK)
	} else {
		sendAPIResponse(w, r, nil, "Not Found", http.StatusNotFound)
	}
}

func getSearchFilters(w http.ResponseWriter, r *http.Request) (int, int, string, error) {
	var err error
	limit := 100
	offset := 0
	order := dataprovider.OrderASC
	if _, ok := r.URL.Query()["limit"]; ok {
		limit, err = strconv.Atoi(r.URL.Query().Get("limit"))
		if err != nil {
			err = errors.New("invalid limit")
			sendAPIResponse(w, r, err, "", http.StatusBadRequest)
			return limit, offset, order, err
		}
		if limit > 500 {
			limit = 500
		}
	}
	if _, ok := r.URL.Query()["offset"]; ok {
		offset, err = strconv.Atoi(r.URL.Query().Get("offset"))
		if err != nil {
			err = errors.New("invalid offset")
			sendAPIResponse(w, r, err, "", http.StatusBadRequest)
			return limit, offset, order, err
		}
	}
	if _, ok := r.URL.Query()["order"]; ok {
		order = r.URL.Query().Get("order")
		if order != dataprovider.OrderASC && order != dataprovider.OrderDESC {
			err = errors.New("invalid order")
			sendAPIResponse(w, r, err, "", http.StatusBadRequest)
			return limit, offset, order, err
		}
	}

	return limit, offset, order, err
}

func renderCompressedFiles(w http.ResponseWriter, conn *Connection, baseDir string, files []string) {
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Accept-Ranges", "none")
	w.Header().Set("Content-Transfer-Encoding", "binary")
	w.WriteHeader(http.StatusOK)

	wr := zip.NewWriter(w)

	for _, file := range files {
		fullPath := path.Join(baseDir, file)
		if err := addZipEntry(wr, conn, fullPath, baseDir); err != nil {
			panic(http.ErrAbortHandler)
		}
	}
	if err := wr.Close(); err != nil {
		conn.Log(logger.LevelWarn, "unable to close zip file: %v", err)
		panic(http.ErrAbortHandler)
	}
}

func addZipEntry(wr *zip.Writer, conn *Connection, entryPath, baseDir string) error {
	info, err := conn.Stat(entryPath, 1)
	if err != nil {
		conn.Log(logger.LevelDebug, "unable to add zip entry %#v, stat error: %v", entryPath, err)
		return err
	}
	if info.IsDir() {
		_, err := wr.Create(getZipEntryName(entryPath, baseDir) + "/")
		if err != nil {
			conn.Log(logger.LevelDebug, "unable to create zip entry %#v: %v", entryPath, err)
			return err
		}
		contents, err := conn.ReadDir(entryPath)
		if err != nil {
			conn.Log(logger.LevelDebug, "unable to add zip entry %#v, read dir error: %v", entryPath, err)
			return err
		}
		for _, info := range contents {
			fullPath := path.Join(entryPath, info.Name())
			if err := addZipEntry(wr, conn, fullPath, baseDir); err != nil {
				return err
			}
		}
		return nil
	}
	if !info.Mode().IsRegular() {
		// we only allow regular files
		conn.Log(logger.LevelDebug, "skipping zip entry for non regular file %#v", entryPath)
		return nil
	}
	reader, err := conn.getFileReader(entryPath, 0, http.MethodGet)
	if err != nil {
		conn.Log(logger.LevelDebug, "unable to add zip entry %#v, cannot open file: %v", entryPath, err)
		return err
	}
	defer reader.Close()

	f, err := wr.Create(getZipEntryName(entryPath, baseDir))
	if err != nil {
		conn.Log(logger.LevelDebug, "unable to create zip entry %#v: %v", entryPath, err)
		return err
	}
	_, err = io.Copy(f, reader)
	return err
}

func getZipEntryName(entryPath, baseDir string) string {
	entryPath = strings.TrimPrefix(entryPath, baseDir)
	return strings.TrimPrefix(entryPath, "/")
}
