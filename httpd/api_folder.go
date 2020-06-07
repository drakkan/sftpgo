package httpd

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/vfs"
)

func getFolders(w http.ResponseWriter, r *http.Request) {
	var err error
	limit := 100
	offset := 0
	order := dataprovider.OrderASC
	folderPath := ""
	if _, ok := r.URL.Query()["limit"]; ok {
		limit, err = strconv.Atoi(r.URL.Query().Get("limit"))
		if err != nil {
			err = errors.New("Invalid limit")
			sendAPIResponse(w, r, err, "", http.StatusBadRequest)
			return
		}
		if limit > 500 {
			limit = 500
		}
	}
	if _, ok := r.URL.Query()["offset"]; ok {
		offset, err = strconv.Atoi(r.URL.Query().Get("offset"))
		if err != nil {
			err = errors.New("Invalid offset")
			sendAPIResponse(w, r, err, "", http.StatusBadRequest)
			return
		}
	}
	if _, ok := r.URL.Query()["order"]; ok {
		order = r.URL.Query().Get("order")
		if order != dataprovider.OrderASC && order != dataprovider.OrderDESC {
			err = errors.New("Invalid order")
			sendAPIResponse(w, r, err, "", http.StatusBadRequest)
			return
		}
	}
	if _, ok := r.URL.Query()["folder_path"]; ok {
		folderPath = r.URL.Query().Get("folder_path")
	}
	folders, err := dataprovider.GetFolders(dataProvider, limit, offset, order, folderPath)
	if err == nil {
		render.JSON(w, r, folders)
	} else {
		sendAPIResponse(w, r, err, "", http.StatusInternalServerError)
	}
}

func addFolder(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	var folder vfs.BaseVirtualFolder
	err := render.DecodeJSON(r.Body, &folder)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	err = dataprovider.AddFolder(dataProvider, folder)
	if err == nil {
		folder, err = dataprovider.GetFolderByPath(dataProvider, folder.MappedPath)
		if err == nil {
			render.JSON(w, r, folder)
		} else {
			sendAPIResponse(w, r, err, "", http.StatusInternalServerError)
		}
	} else {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
	}
}

func deleteFolderByPath(w http.ResponseWriter, r *http.Request) {
	var folderPath string
	if _, ok := r.URL.Query()["folder_path"]; ok {
		folderPath = r.URL.Query().Get("folder_path")
	}
	if len(folderPath) == 0 {
		err := errors.New("a non-empty folder path is required")
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}

	folder, err := dataprovider.GetFolderByPath(dataProvider, folderPath)
	if _, ok := err.(*dataprovider.RecordNotFoundError); ok {
		sendAPIResponse(w, r, err, "", http.StatusNotFound)
		return
	} else if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusInternalServerError)
		return
	}
	err = dataprovider.DeleteFolder(dataProvider, folder)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusInternalServerError)
	} else {
		sendAPIResponse(w, r, err, "Folder deleted", http.StatusOK)
	}
}
