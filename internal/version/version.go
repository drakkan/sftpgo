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

// Package version defines SFTPGo version details
package version

import "strings"

const (
	version = "2.7.99-dev"
	appName = "SFTPGo"
)

var (
	commit = ""
	date   = ""
	info   Info
)

var (
	config string
)

// Info defines version details
type Info struct {
	Version    string   `json:"version"`
	BuildDate  string   `json:"build_date"`
	CommitHash string   `json:"commit_hash"`
	Features   []string `json:"features"`
}

// GetAsString returns the string representation of the version
func GetAsString() string {
	var sb strings.Builder
	sb.WriteString(info.Version)
	if info.CommitHash != "" {
		sb.WriteString("-")
		sb.WriteString(info.CommitHash)
	}
	if info.BuildDate != "" {
		sb.WriteString("-")
		sb.WriteString(info.BuildDate)
	}
	if len(info.Features) > 0 {
		sb.WriteString(" ")
		sb.WriteString(strings.Join(info.Features, " "))
	}
	return sb.String()
}

func init() {
	info = Info{
		Version:    version,
		CommitHash: commit,
		BuildDate:  date,
	}
}

// AddFeature adds a feature description
func AddFeature(feature string) {
	info.Features = append(info.Features, feature)
}

// Get returns the Info struct
func Get() Info {
	return info
}

// SetConfig sets the version configuration
func SetConfig(val string) {
	config = val
}

// GetServerVersion returns the server version according to the configuration
// and the provided parameters.
func GetServerVersion(separator string, addHash bool) string {
	var sb strings.Builder
	sb.WriteString(appName)
	if config != "short" {
		sb.WriteString(separator)
		sb.WriteString(info.Version)
	}
	if addHash {
		sb.WriteString(separator)
		sb.WriteString(info.CommitHash)
	}
	return sb.String()
}

// GetVersionHash returns the server identification string with the commit hash.
func GetVersionHash() string {
	var sb strings.Builder
	sb.WriteString(appName)
	sb.WriteString("-")
	sb.WriteString(info.CommitHash)
	return sb.String()
}
