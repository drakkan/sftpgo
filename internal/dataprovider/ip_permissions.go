package dataprovider

import (
	"os"
	"strings"
)

const (
	envIPFilterEnabled = "SFTPGO_IP_FILTER_ENABLED"
	envIPFilterMode    = "SFTPGO_IP_FILTER_MODE"
	envIPFilterScope   = "SFTPGO_IP_FILTER_SCOPE"

	ipFilterModeAllowUnmatched = "allow_unmatched"
	ipFilterModeDenyUnmatched  = "deny_unmatched"
	ipFilterScopeDataOnly      = "data_only"
	ipFilterScopeAllRequests   = "all_requests"
)

func isWritePermission(permission string) bool {
	switch permission {
	case PermUpload, PermOverwrite, PermCreateDirs, PermRename, PermRenameFiles, PermRenameDirs,
		PermDelete, PermDeleteFiles, PermDeleteDirs, PermCreateSymlinks, PermChmod, PermChown,
		PermChtimes, PermCopy:
		return true
	default:
		return false
	}
}

func isReadPermission(permission string) bool {
	switch permission {
	case PermDownload, PermListItems, PermCopy:
		return true
	default:
		return false
	}
}

func getIPFilterMode() string {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv(envIPFilterMode)))
	switch mode {
	case "", ipFilterModeAllowUnmatched:
		return ipFilterModeAllowUnmatched
	case ipFilterModeDenyUnmatched:
		return ipFilterModeDenyUnmatched
	default:
		return ipFilterModeAllowUnmatched
	}
}

func getIPFilterScope() string {
	scope := strings.ToLower(strings.TrimSpace(os.Getenv(envIPFilterScope)))
	switch scope {
	case "", ipFilterScopeDataOnly:
		return ipFilterScopeDataOnly
	case ipFilterScopeAllRequests:
		return ipFilterScopeAllRequests
	default:
		return ipFilterScopeDataOnly
	}
}

func normalizeIPListProtocol(protocol string) string {
	switch strings.ToUpper(strings.TrimSpace(protocol)) {
	case "SFTP", "SCP", protocolSSH:
		return protocolSSH
	case protocolFTP:
		return protocolFTP
	case protocolWebDAV:
		return protocolWebDAV
	case protocolHTTP, "HTTPSHARE", "OIDC":
		return protocolHTTP
	default:
		return protocol
	}
}

func isIPFilterEnabled() bool {
	val := strings.TrimSpace(os.Getenv(envIPFilterEnabled))
	switch strings.ToLower(val) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func isPermissionAllowedForIP(permission, remoteIP, protocol string) bool {
	if !isIPFilterEnabled() {
		return true
	}
	if getIPFilterScope() != ipFilterScopeDataOnly && getIPFilterScope() != ipFilterScopeAllRequests {
		return true
	}
	if remoteIP == "" {
		return false
	}
	entry, ok, err := GetIPListEntryForIP(remoteIP, normalizeIPListProtocol(protocol), IPListTypeAllowList)
	if err != nil {
		return false
	}
	if !ok {
		return getIPFilterMode() != ipFilterModeDenyUnmatched
	}
	if isWritePermission(permission) && !entry.AllowsUpload() {
		return false
	}
	if isReadPermission(permission) && !entry.AllowsDownload() {
		return false
	}
	return true
}
