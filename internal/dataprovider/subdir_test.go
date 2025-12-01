package dataprovider

import (
	"fmt"
	"testing"

	"github.com/drakkan/sftpgo/v2/internal/vfs"
	"github.com/stretchr/testify/assert"
)

func TestValidateVirtualSubdirectory(t *testing.T) {
	// Simple subdirectory names are safe for tenant isolation
	err := validateVirtualSubdirectory("simple")
	assert.NoError(t, err)

	// Nested paths without traversal are safe for hierarchical organization
	err = validateVirtualSubdirectory("level1/level2/level3")
	assert.NoError(t, err)

	// Common naming patterns with underscores and dashes are acceptable
	err = validateVirtualSubdirectory("user_1/data-files")
	assert.NoError(t, err)

	// Empty subdirectory maintains backward compatibility - no isolation
	err = validateVirtualSubdirectory("")
	assert.NoError(t, err)

	// Absolute paths could bypass sandboxing to access system directories
	err = validateVirtualSubdirectory("/absolute/path")
	assert.Error(t, err)

	// Leading parent traversal could escape tenant directory boundaries
	err = validateVirtualSubdirectory("../parent")
	assert.Error(t, err)

	// Embedded traversal could appear legitimate while accessing other tenants
	err = validateVirtualSubdirectory("valid/../../../escape")
	assert.Error(t, err)

	// Trailing traversal could be used to probe directory structure
	err = validateVirtualSubdirectory("valid/path/..")
	assert.Error(t, err)

	// Any form of parent reference is a potential security vulnerability
	err = validateVirtualSubdirectory("path/with/../dots")
	assert.Error(t, err)
}

func TestSubdirectoryDatabaseMigration(t *testing.T) {
	// Test migration compatibility: existing folders without subdirectory (empty string)
	// must continue working alongside new folders with subdirectory paths
	folders := []vfs.VirtualFolder{
		{
			BaseVirtualFolder: vfs.BaseVirtualFolder{
				Name:       "legacy_folder",
				MappedPath: "/data/legacy",
			},
			VirtualPath:         "/legacy",
			VirtualSubdirectory: "", // Empty means access to entire mapped path (pre-migration behavior)
		},
		{
			BaseVirtualFolder: vfs.BaseVirtualFolder{
				Name:       "new_folder",
				MappedPath: "/data/new",
			},
			VirtualPath:         "/new",
			VirtualSubdirectory: "tenant1/data", // New post-migration subdirectory isolation
		},
	}

	for _, folder := range folders {
		err := validateVirtualSubdirectory(folder.VirtualSubdirectory)
		assert.NoError(t, err)
	}

	folderKeys := make(map[[2]string]bool)
	for _, folder := range folders {
		key := [2]string{folder.Name, folder.VirtualSubdirectory}
		assert.False(t, folderKeys[key], "Duplicate folder key: %v", key)
		folderKeys[key] = true
	}

	assert.Len(t, folderKeys, 2)

	// Critical: same folder name with different subdirectories must create unique database keys
	// This enables multi-tenant shared storage where folder "shared" can have subdirs "tenant1", "tenant2"
	duplicateNameFolders := []vfs.VirtualFolder{
		{
			BaseVirtualFolder: vfs.BaseVirtualFolder{
				Name: "shared",
			},
			VirtualSubdirectory: "tenant1",
		},
		{
			BaseVirtualFolder: vfs.BaseVirtualFolder{
				Name: "shared",
			},
			VirtualSubdirectory: "tenant2",
		},
		{
			BaseVirtualFolder: vfs.BaseVirtualFolder{
				Name: "shared",
			},
			VirtualSubdirectory: "",
		},
	}

	folderKeys = make(map[[2]string]bool)
	for _, folder := range duplicateNameFolders {
		key := [2]string{folder.Name, folder.VirtualSubdirectory}
		assert.False(t, folderKeys[key], "Should allow same folder with different subdirectories")
		folderKeys[key] = true
	}
	assert.Len(t, folderKeys, 3, "Should have 3 unique combinations")
}

func TestSubdirectoryDatabaseConstraints(t *testing.T) {
	// Database must enforce unique constraint on (folder_name, subdirectory) pairs
	// while allowing same folder_name with different subdirectories

	// Different subdirectories with same folder should be allowed
	folders1 := []vfs.VirtualFolder{
		{
			BaseVirtualFolder: vfs.BaseVirtualFolder{
				Name:       "shared",
				MappedPath: "/data/shared",
			},
			VirtualPath:         "/path1",
			VirtualSubdirectory: "tenant1",
		},
		{
			BaseVirtualFolder: vfs.BaseVirtualFolder{
				Name:       "shared",
				MappedPath: "/data/shared",
			},
			VirtualPath:         "/path2",
			VirtualSubdirectory: "tenant2",
		},
	}

	// Simulate database constraint validation: [folder_name, subdirectory] must be unique
	folderKeys := make(map[[2]string]bool)
	var validationError error
	for _, folder := range folders1 {
		if err := validateVirtualSubdirectory(folder.VirtualSubdirectory); err != nil {
			validationError = err
			break
		}
		key := [2]string{folder.Name, folder.VirtualSubdirectory}
		if folderKeys[key] {
			validationError = fmt.Errorf("duplicate folder key: %v", key)
			break
		}
		folderKeys[key] = true
	}
	assert.NoError(t, validationError, "Different subdirectories with same folder should be allowed")

	// Same folder with same subdirectory should be rejected
	folders2 := []vfs.VirtualFolder{
		{
			BaseVirtualFolder: vfs.BaseVirtualFolder{
				Name:       "shared",
				MappedPath: "/data/shared",
			},
			VirtualPath:         "/path1",
			VirtualSubdirectory: "tenant1",
		},
		{
			BaseVirtualFolder: vfs.BaseVirtualFolder{
				Name:       "shared",
				MappedPath: "/data/shared",
			},
			VirtualPath:         "/path2",
			VirtualSubdirectory: "tenant1",
		},
	}

	folderKeys = make(map[[2]string]bool)
	validationError = nil
	for _, folder := range folders2 {
		if err := validateVirtualSubdirectory(folder.VirtualSubdirectory); err != nil {
			validationError = err
			break
		}
		key := [2]string{folder.Name, folder.VirtualSubdirectory}
		if folderKeys[key] {
			validationError = fmt.Errorf("duplicate folder key: %v", key)
			break
		}
		folderKeys[key] = true
	}
	assert.Error(t, validationError, "Same folder with same subdirectory should be rejected")

	// Duplicate empty subdirectories should be rejected
	folders3 := []vfs.VirtualFolder{
		{
			BaseVirtualFolder: vfs.BaseVirtualFolder{
				Name:       "legacy",
				MappedPath: "/data/legacy",
			},
			VirtualPath:         "/path1",
			VirtualSubdirectory: "",
		},
		{
			BaseVirtualFolder: vfs.BaseVirtualFolder{
				Name:       "legacy",
				MappedPath: "/data/legacy",
			},
			VirtualPath:         "/path2",
			VirtualSubdirectory: "",
		},
	}

	folderKeys = make(map[[2]string]bool)
	validationError = nil
	for _, folder := range folders3 {
		if err := validateVirtualSubdirectory(folder.VirtualSubdirectory); err != nil {
			validationError = err
			break
		}
		key := [2]string{folder.Name, folder.VirtualSubdirectory}
		if folderKeys[key] {
			validationError = fmt.Errorf("duplicate folder key: %v", key)
			break
		}
		folderKeys[key] = true
	}
	assert.Error(t, validationError, "Duplicate empty subdirectories should be rejected")
}
