// Copyright (C) 2026 xrogers
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

package vfs

import "testing"

func pointer(value string) *string {
	return &value
}

// Objects written before the rename keep their modification time under the old key.
func TestLastModifiedMetadataNames(t *testing.T) {
	tests := []struct {
		name     string
		metadata map[string]string
		want     int64
	}{
		{"new key", map[string]string{lastModifiedField: "1000"}, 1000},
		{"legacy key", map[string]string{legacyLastModifiedField: "2000"}, 2000},
		{"new key wins", map[string]string{legacyLastModifiedField: "2000", lastModifiedField: "1000"}, 1000},
		{"invalid new key falls back", map[string]string{legacyLastModifiedField: "2000", lastModifiedField: "x"}, 2000},
		{"neither", map[string]string{"other": "1"}, 0},
	}
	for _, test := range tests {
		if got := getLastModified(test.metadata); got != test.want {
			t.Errorf("%s: getLastModified = %d, want %d", test.name, got, test.want)
		}
		azure := make(map[string]*string)
		for key, value := range test.metadata {
			azure[key] = pointer(value)
		}
		if got := getAzureLastModified(azure); got != test.want {
			t.Errorf("%s: getAzureLastModified = %d, want %d", test.name, got, test.want)
		}
	}
	// Azure returns metadata keys with its own capitalization.
	if got := getAzureLastModified(map[string]*string{"Sftpgo_last_modified": pointer("3000")}); got != 3000 {
		t.Errorf("capitalized legacy key: got %d, want 3000", got)
	}
	if !isLastModifiedField("GONAS_LAST_MODIFIED") || !isLastModifiedField(legacyLastModifiedField) || isLastModifiedField("other") {
		t.Error("isLastModifiedField does not recognize both names")
	}
}
