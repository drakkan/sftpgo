package httpd

import (
	"context"
	"net/http"

	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/vfs"
)

func getFolders(w http.ResponseWriter, r *http.Request) {
	limit, offset, order, err := getSearchFilters(w, r)
	if err != nil {
		return
	}

	folders, err := dataprovider.GetFolders(limit, offset, order)
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
	err = dataprovider.AddFolder(&folder)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	renderFolder(w, r, folder.Name, http.StatusCreated)
}

func updateFolder(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	var err error

	name := getURLParam(r, "name")
	folder, err := dataprovider.GetFolderByName(name)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	folderID := folder.ID
	err = render.DecodeJSON(r.Body, &folder)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	folder.ID = folderID
	folder.Name = name
	err = dataprovider.UpdateFolder(&folder)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, nil, "Folder updated", http.StatusOK)
}

func renderFolder(w http.ResponseWriter, r *http.Request, name string, status int) {
	folder, err := dataprovider.GetFolderByName(name)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	if status != http.StatusOK {
		ctx := context.WithValue(r.Context(), render.StatusCtxKey, status)
		render.JSON(w, r.WithContext(ctx), folder)
	} else {
		render.JSON(w, r, folder)
	}
}

func getFolderByName(w http.ResponseWriter, r *http.Request) {
	name := getURLParam(r, "name")
	renderFolder(w, r, name, http.StatusOK)
}

func deleteFolder(w http.ResponseWriter, r *http.Request) {
	name := getURLParam(r, "name")
	err := dataprovider.DeleteFolder(name)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "Folder deleted", http.StatusOK)
}
