package utils

import "strings"

const version = "0.9.6-dev"

var (
	commit      = ""
	date        = ""
	versionInfo VersionInfo
)

// VersionInfo defines version details
type VersionInfo struct {
	Version    string   `json:"version"`
	BuildDate  string   `json:"build_date"`
	CommitHash string   `json:"commit_hash"`
	Features   []string `json:"features"`
}

// GetVersionAsString returns the string representation of the VersionInfo struct
func (v *VersionInfo) GetVersionAsString() string {
	var sb strings.Builder
	sb.WriteString(v.Version)
	if len(v.CommitHash) > 0 {
		sb.WriteString("-")
		sb.WriteString(v.CommitHash)
	}
	if len(v.BuildDate) > 0 {
		sb.WriteString("-")
		sb.WriteString(v.BuildDate)
	}
	if len(v.Features) > 0 {
		sb.WriteString(" ")
		sb.WriteString(strings.Join(v.Features, " "))
	}
	return sb.String()
}

// AddFeature adds a feature description
func AddFeature(feature string) {
	versionInfo.Features = append(versionInfo.Features, feature)
}

func init() {
	versionInfo = VersionInfo{
		Version:    version,
		CommitHash: commit,
		BuildDate:  date,
	}
}
