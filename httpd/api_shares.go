package httpd

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/go-chi/render"
	"github.com/rs/xid"

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/util"
)

func getShares(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	limit, offset, order, err := getSearchFilters(w, r)
	if err != nil {
		return
	}

	shares, err := dataprovider.GetShares(limit, offset, order, claims.Username)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	render.JSON(w, r, shares)
}

func getShareByID(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	shareID := getURLParam(r, "id")
	share, err := dataprovider.ShareExists(shareID, claims.Username)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	share.HideConfidentialData()

	render.JSON(w, r, share)
}

func addShare(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	var share dataprovider.Share
	err = render.DecodeJSON(r.Body, &share)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	share.ID = 0
	share.ShareID = util.GenerateUniqueID()
	share.LastUseAt = 0
	share.Username = claims.Username
	if share.Name == "" {
		share.Name = share.ShareID
	}
	err = dataprovider.AddShare(&share, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr))
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	w.Header().Add("Location", fmt.Sprintf("%v/%v", userSharesPath, share.ShareID))
	w.Header().Add("X-Object-ID", share.ShareID)
	sendAPIResponse(w, r, nil, "Share created", http.StatusCreated)
}

func updateShare(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	shareID := getURLParam(r, "id")
	share, err := dataprovider.ShareExists(shareID, claims.Username)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	oldPassword := share.Password
	err = render.DecodeJSON(r.Body, &share)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}

	share.ShareID = shareID
	share.Username = claims.Username
	if share.Password == redactedSecret {
		share.Password = oldPassword
	}
	if err := dataprovider.UpdateShare(&share, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr)); err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, nil, "Share updated", http.StatusOK)
}

func deleteShare(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	shareID := getURLParam(r, "id")
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}

	err = dataprovider.DeleteShare(shareID, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr))
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "Share deleted", http.StatusOK)
}

func downloadFromShare(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	share, connection, err := checkPublicShare(w, r, dataprovider.ShareScopeRead)
	if err != nil {
		return
	}

	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	dataprovider.UpdateShareLastUse(&share, 1) //nolint:errcheck
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"share-%v.zip\"", share.ShareID))
	renderCompressedFiles(w, connection, "/", share.Paths, &share)
}

func uploadToShare(w http.ResponseWriter, r *http.Request) {
	if maxUploadFileSize > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, maxUploadFileSize)
	}
	share, connection, err := checkPublicShare(w, r, dataprovider.ShareScopeWrite)
	if err != nil {
		return
	}

	common.Connections.Add(connection)
	defer common.Connections.Remove(connection.GetID())

	err = r.ParseMultipartForm(maxMultipartMem)
	if err != nil {
		sendAPIResponse(w, r, err, "Unable to parse multipart form", http.StatusBadRequest)
		return
	}
	defer r.MultipartForm.RemoveAll() //nolint:errcheck

	files := r.MultipartForm.File["filenames"]
	if len(files) == 0 {
		sendAPIResponse(w, r, nil, "No files uploaded!", http.StatusBadRequest)
		return
	}
	if share.MaxTokens > 0 {
		if len(files) > (share.MaxTokens - share.UsedTokens) {
			sendAPIResponse(w, r, nil, "Allowed usage exceeded", http.StatusBadRequest)
			return
		}
	}
	dataprovider.UpdateShareLastUse(&share, len(files)) //nolint:errcheck

	numUploads := doUploadFiles(w, r, connection, share.Paths[0], files)
	if numUploads != len(files) {
		dataprovider.UpdateShareLastUse(&share, numUploads-len(files)) //nolint:errcheck
	}
}

func checkPublicShare(w http.ResponseWriter, r *http.Request, shareShope dataprovider.ShareScope,
) (dataprovider.Share, *Connection, error) {
	shareID := getURLParam(r, "id")
	share, err := dataprovider.ShareExists(shareID, "")
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return share, nil, err
	}
	if share.Scope != shareShope {
		sendAPIResponse(w, r, nil, "Invalid share scope", http.StatusForbidden)
		return share, nil, errors.New("invalid share scope")
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	ok, err := share.IsUsable(ipAddr)
	if !ok || err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return share, nil, errors.New("login not allowed")
	}
	if share.Password != "" {
		_, password, ok := r.BasicAuth()
		if !ok {
			w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
			sendAPIResponse(w, r, nil, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return share, nil, dataprovider.ErrInvalidCredentials
		}
		match, err := share.CheckPassword(password)
		if !match || err != nil {
			w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
			sendAPIResponse(w, r, nil, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return share, nil, dataprovider.ErrInvalidCredentials
		}
	}
	user, err := dataprovider.UserExists(share.Username)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return share, nil, err
	}
	connID := xid.New().String()
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, common.ProtocolHTTPShare, util.GetHTTPLocalAddress(r),
			r.RemoteAddr, user),
		request: r,
	}

	return share, connection, nil
}
