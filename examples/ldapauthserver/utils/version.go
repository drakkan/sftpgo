package utils

const version = "0.1.0-dev"

var (
	commit      = ""
	date        = ""
	versionInfo VersionInfo
)

// VersionInfo defines version details
type VersionInfo struct {
	Version    string `json:"version"`
	BuildDate  string `json:"build_date"`
	CommitHash string `json:"commit_hash"`
}

func init() {
	versionInfo = VersionInfo{
		Version:    version,
		CommitHash: commit,
		BuildDate:  date,
	}
}

// GetVersionAsString returns the string representation of the VersionInfo struct
func (v *VersionInfo) GetVersionAsString() string {
	versionString := v.Version
	if len(v.CommitHash) > 0 {
		versionString += "-" + v.CommitHash
	}
	if len(v.BuildDate) > 0 {
		versionString += "-" + v.BuildDate
	}
	return versionString
}

// GetAppVersion returns VersionInfo struct
func GetAppVersion() VersionInfo {
	return versionInfo
}
