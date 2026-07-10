// Copyright (C) 2026 Nicola Murino
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

package dataprovider

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/sftpgo/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

func TestNormalizeMappedSubdirectory(t *testing.T) {
	for in, want := range map[string]string{
		"simple":               "simple",
		"level1/level2/level3": "level1/level2/level3",
		"user_1/data-files":    "user_1/data-files",
		"release..notes":       "release..notes",
		"a//b/./c":             "a/b/c",
		`tenant\data`:          "tenant/data", // backslash is treated as a separator
		"":                     "",
		".":                    "",
	} {
		got, err := normalizeMappedSubdirectory(in)
		assert.NoError(t, err, "input %q", in)
		assert.Equal(t, want, got, "input %q", in)
	}
	for _, in := range []string{"/absolute/path", "../parent", "valid/../../../escape", "..", `..\..\secrets`} {
		_, err := normalizeMappedSubdirectory(in)
		assert.ErrorIs(t, err, errInvalidMappedSubdirectory, "input %q", in)
	}
	// over-length is rejected (the column is part of a MySQL unique index)
	_, err := normalizeMappedSubdirectory(strings.Repeat("a", 256))
	assert.Error(t, err)
	// an interior ".." that stays inside the root is collapsed, not rejected
	got, err := normalizeMappedSubdirectory("path/with/../dots")
	assert.NoError(t, err)
	assert.Equal(t, "path/dots", got)
}

func TestValidateAssociatedVirtualFoldersSubdirectory(t *testing.T) {
	// the same folder mapped to different subdirectories is allowed
	folders, err := validateAssociatedVirtualFolders([]vfs.VirtualFolder{
		{
			BaseVirtualFolder:  vfs.BaseVirtualFolder{Name: "shared", MappedPath: "/data/shared"},
			VirtualPath:        "/one",
			MappedSubdirectory: "tenant1",
		},
		{
			BaseVirtualFolder:  vfs.BaseVirtualFolder{Name: "shared", MappedPath: "/data/shared"},
			VirtualPath:        "/two",
			MappedSubdirectory: "tenant2/data",
		},
	})
	require.NoError(t, err)
	require.Len(t, folders, 2)
	assert.Equal(t, "tenant1", folders[0].MappedSubdirectory)
	assert.Equal(t, "tenant2/data", folders[1].MappedSubdirectory)
	// only the folder name survives from the supplied BaseVirtualFolder
	assert.Empty(t, folders[0].MappedPath)

	// the same folder with the same subdirectory is a duplicate
	_, err = validateAssociatedVirtualFolders([]vfs.VirtualFolder{
		{BaseVirtualFolder: vfs.BaseVirtualFolder{Name: "shared"}, VirtualPath: "/one", MappedSubdirectory: "same"},
		{BaseVirtualFolder: vfs.BaseVirtualFolder{Name: "shared"}, VirtualPath: "/two", MappedSubdirectory: "same"},
	})
	assert.Error(t, err)

	_, err = validateAssociatedVirtualFolders([]vfs.VirtualFolder{
		{BaseVirtualFolder: vfs.BaseVirtualFolder{Name: "shared"}, VirtualPath: "/one", MappedSubdirectory: "../escape"},
	})
	assert.Error(t, err)
}

func TestMappedSubdirectoryQuotaGuard(t *testing.T) {
	_, err := validateAssociatedVirtualFolders([]vfs.VirtualFolder{
		{
			BaseVirtualFolder:  vfs.BaseVirtualFolder{Name: "shared"},
			VirtualPath:        "/one",
			MappedSubdirectory: "tenant1",
			QuotaSize:          100,
			QuotaFiles:         10,
		},
	})
	assert.Error(t, err)
	// unlimited (0/0) and included-in-user-quota (-1/-1) remain valid
	for _, q := range [][2]int64{{0, 0}, {-1, -1}} {
		_, err := validateAssociatedVirtualFolders([]vfs.VirtualFolder{
			{
				BaseVirtualFolder:  vfs.BaseVirtualFolder{Name: "shared"},
				VirtualPath:        "/one",
				MappedSubdirectory: "tenant1",
				QuotaSize:          q[0],
				QuotaFiles:         int(q[1]),
			},
		})
		assert.NoError(t, err, "quota %v", q)
	}
}

func TestVirtualFolderEffectiveMappedPath(t *testing.T) {
	base := filepath.Join(string(filepath.Separator)+"data", "shared")
	v := vfs.VirtualFolder{BaseVirtualFolder: vfs.BaseVirtualFolder{MappedPath: base}}
	assert.Equal(t, base, v.GetEffectiveMappedPath())
	v.MappedSubdirectory = "tenant1/data"
	assert.Equal(t, filepath.Join(base, "tenant1", "data"), v.GetEffectiveMappedPath())
}

func TestGroupMappedSubdirectoryPlaceholder(t *testing.T) {
	user := User{
		BaseUser: sdk.BaseUser{Username: "alice"},
		Groups:   []sdk.GroupMapping{{Name: "g", Type: sdk.GroupTypePrimary}},
	}
	group := Group{
		BaseGroup: sdk.BaseGroup{Name: "g"},
		VirtualFolders: []vfs.VirtualFolder{
			{
				BaseVirtualFolder:  vfs.BaseVirtualFolder{Name: "shared"},
				VirtualPath:        "/data",
				MappedSubdirectory: "%username%/files",
			},
		},
	}
	user.applyGroupSettings(map[string]Group{"g": group})
	require.Len(t, user.VirtualFolders, 1)
	assert.Equal(t, "alice/files", user.VirtualFolders[0].MappedSubdirectory)
}
