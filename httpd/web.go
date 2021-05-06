package httpd

import (
	"path"
	"strings"

	"github.com/drakkan/sftpgo/utils"
)

const (
	page400Title      = "Bad request"
	page403Title      = "Forbidden"
	page404Title      = "Not found"
	page404Body       = "The page you are looking for does not exist."
	page500Title      = "Internal Server Error"
	page500Body       = "The server is unable to fulfill your request."
	webDateTimeFormat = "2006-01-02 15:04:05" // YYYY-MM-DD HH:MM:SS
	redactedSecret    = "[**redacted**]"
	csrfFormToken     = "_form_token"
	csrfHeaderToken   = "X-CSRF-TOKEN"
)

type loginPage struct {
	CurrentURL string
	Version    string
	Error      string
	CSRFToken  string
	StaticURL  string
}

func getSliceFromDelimitedValues(values, delimiter string) []string {
	result := []string{}
	for _, v := range strings.Split(values, delimiter) {
		cleaned := strings.TrimSpace(v)
		if cleaned != "" {
			result = append(result, cleaned)
		}
	}
	return result
}

func getListFromPostFields(value string) map[string][]string {
	result := make(map[string][]string)
	for _, cleaned := range getSliceFromDelimitedValues(value, "\n") {
		if strings.Contains(cleaned, "::") {
			dirExts := strings.Split(cleaned, "::")
			if len(dirExts) > 1 {
				dir := dirExts[0]
				dir = path.Clean(strings.TrimSpace(dir))
				exts := []string{}
				for _, e := range strings.Split(dirExts[1], ",") {
					cleanedExt := strings.TrimSpace(e)
					if cleanedExt != "" {
						exts = append(exts, cleanedExt)
					}
				}
				if dir != "" {
					if _, ok := result[dir]; ok {
						result[dir] = append(result[dir], exts...)
					} else {
						result[dir] = exts
					}
					result[dir] = utils.RemoveDuplicates(result[dir])
				}
			}
		}
	}
	return result
}
