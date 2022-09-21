// Copyright (C) 2019-2022  Nicola Murino
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package dataprovider

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/sftpgo/sdk"

	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/plugin"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

// GroupUserSettings defines the settings to apply to users
type GroupUserSettings struct {
	sdk.BaseGroupUserSettings
	// Filesystem configuration details
	FsConfig vfs.Filesystem `json:"filesystem"`
}

// Group defines an SFTPGo group.
// Groups are used to easily configure similar users
type Group struct {
	sdk.BaseGroup
	// settings to apply to users for whom this is a primary group
	UserSettings GroupUserSettings `json:"user_settings,omitempty"`
	// Mapping between virtual paths and virtual folders
	VirtualFolders []vfs.VirtualFolder `json:"virtual_folders,omitempty"`
}

// GetPermissions returns the permissions as list
func (g *Group) GetPermissions() []sdk.DirectoryPermissions {
	result := make([]sdk.DirectoryPermissions, 0, len(g.UserSettings.Permissions))
	for k, v := range g.UserSettings.Permissions {
		result = append(result, sdk.DirectoryPermissions{
			Path:        k,
			Permissions: v,
		})
	}
	return result
}

// GetAllowedIPAsString returns the allowed IP as comma separated string
func (g *Group) GetAllowedIPAsString() string {
	return strings.Join(g.UserSettings.Filters.AllowedIP, ",")
}

// GetDeniedIPAsString returns the denied IP as comma separated string
func (g *Group) GetDeniedIPAsString() string {
	return strings.Join(g.UserSettings.Filters.DeniedIP, ",")
}

// HasExternalAuth returns true if the external authentication is globally enabled
// and it is not disabled for this group
func (g *Group) HasExternalAuth() bool {
	if g.UserSettings.Filters.Hooks.ExternalAuthDisabled {
		return false
	}
	if config.ExternalAuthHook != "" {
		return true
	}
	return plugin.Handler.HasAuthenticators()
}

// SetEmptySecretsIfNil sets the secrets to empty if nil
func (g *Group) SetEmptySecretsIfNil() {
	g.UserSettings.FsConfig.SetEmptySecretsIfNil()
	for idx := range g.VirtualFolders {
		vfolder := &g.VirtualFolders[idx]
		vfolder.FsConfig.SetEmptySecretsIfNil()
	}
}

// PrepareForRendering prepares a group for rendering.
// It hides confidential data and set to nil the empty secrets
// so they are not serialized
func (g *Group) PrepareForRendering() {
	g.UserSettings.FsConfig.HideConfidentialData()
	g.UserSettings.FsConfig.SetNilSecretsIfEmpty()
	for idx := range g.VirtualFolders {
		folder := &g.VirtualFolders[idx]
		folder.PrepareForRendering()
	}
}

// RenderAsJSON implements the renderer interface used within plugins
func (g *Group) RenderAsJSON(reload bool) ([]byte, error) {
	if reload {
		group, err := provider.groupExists(g.Name)
		if err != nil {
			providerLog(logger.LevelError, "unable to reload group before rendering as json: %v", err)
			return nil, err
		}
		group.PrepareForRendering()
		return json.Marshal(group)
	}
	g.PrepareForRendering()
	return json.Marshal(g)
}

// GetEncryptionAdditionalData returns the additional data to use for AEAD
func (g *Group) GetEncryptionAdditionalData() string {
	return fmt.Sprintf("group_%v", g.Name)
}

// HasRedactedSecret returns true if the user has a redacted secret
func (g *Group) hasRedactedSecret() bool {
	for idx := range g.VirtualFolders {
		folder := &g.VirtualFolders[idx]
		if folder.HasRedactedSecret() {
			return true
		}
	}

	return g.UserSettings.FsConfig.HasRedactedSecret()
}

func (g *Group) validate() error {
	g.SetEmptySecretsIfNil()
	if g.Name == "" {
		return util.NewValidationError("name is mandatory")
	}
	if config.NamingRules&1 == 0 && !usernameRegex.MatchString(g.Name) {
		return util.NewValidationError(fmt.Sprintf("name %#v is not valid, the following characters are allowed: a-zA-Z0-9-_.~", g.Name))
	}
	if g.hasRedactedSecret() {
		return util.NewValidationError("cannot save a user with a redacted secret")
	}
	vfolders, err := validateAssociatedVirtualFolders(g.VirtualFolders)
	if err != nil {
		return err
	}
	g.VirtualFolders = vfolders
	return g.validateUserSettings()
}

func (g *Group) validateUserSettings() error {
	if g.UserSettings.HomeDir != "" {
		g.UserSettings.HomeDir = filepath.Clean(g.UserSettings.HomeDir)
		if !filepath.IsAbs(g.UserSettings.HomeDir) {
			return util.NewValidationError(fmt.Sprintf("home_dir must be an absolute path, actual value: %v",
				g.UserSettings.HomeDir))
		}
	}
	if err := g.UserSettings.FsConfig.Validate(g.GetEncryptionAdditionalData()); err != nil {
		return err
	}
	if g.UserSettings.TotalDataTransfer > 0 {
		// if a total data transfer is defined we reset the separate upload and download limits
		g.UserSettings.UploadDataTransfer = 0
		g.UserSettings.DownloadDataTransfer = 0
	}
	if len(g.UserSettings.Permissions) > 0 {
		permissions, err := validateUserPermissions(g.UserSettings.Permissions)
		if err != nil {
			return err
		}
		g.UserSettings.Permissions = permissions
	}
	if err := validateBaseFilters(&g.UserSettings.Filters); err != nil {
		return err
	}
	if !g.HasExternalAuth() {
		g.UserSettings.Filters.ExternalAuthCacheTime = 0
	}
	g.UserSettings.Filters.UserType = ""
	return nil
}

func (g *Group) getACopy() Group {
	users := make([]string, len(g.Users))
	copy(users, g.Users)
	admins := make([]string, len(g.Admins))
	copy(admins, g.Admins)
	virtualFolders := make([]vfs.VirtualFolder, 0, len(g.VirtualFolders))
	for idx := range g.VirtualFolders {
		vfolder := g.VirtualFolders[idx].GetACopy()
		virtualFolders = append(virtualFolders, vfolder)
	}
	permissions := make(map[string][]string)
	for k, v := range g.UserSettings.Permissions {
		perms := make([]string, len(v))
		copy(perms, v)
		permissions[k] = perms
	}

	return Group{
		BaseGroup: sdk.BaseGroup{
			ID:          g.ID,
			Name:        g.Name,
			Description: g.Description,
			CreatedAt:   g.CreatedAt,
			UpdatedAt:   g.UpdatedAt,
			Users:       users,
			Admins:      admins,
		},
		UserSettings: GroupUserSettings{
			BaseGroupUserSettings: sdk.BaseGroupUserSettings{
				HomeDir:              g.UserSettings.HomeDir,
				MaxSessions:          g.UserSettings.MaxSessions,
				QuotaSize:            g.UserSettings.QuotaSize,
				QuotaFiles:           g.UserSettings.QuotaFiles,
				Permissions:          permissions,
				UploadBandwidth:      g.UserSettings.UploadBandwidth,
				DownloadBandwidth:    g.UserSettings.DownloadBandwidth,
				UploadDataTransfer:   g.UserSettings.UploadDataTransfer,
				DownloadDataTransfer: g.UserSettings.DownloadDataTransfer,
				TotalDataTransfer:    g.UserSettings.TotalDataTransfer,
				Filters:              copyBaseUserFilters(g.UserSettings.Filters),
			},
			FsConfig: g.UserSettings.FsConfig.GetACopy(),
		},
		VirtualFolders: virtualFolders,
	}
}

// GetMembersAsString returns a string representation for the group members
func (g *Group) GetMembersAsString() string {
	var sb strings.Builder
	if len(g.Users) > 0 {
		sb.WriteString(fmt.Sprintf("Users: %d. ", len(g.Users)))
	}
	if len(g.Admins) > 0 {
		sb.WriteString(fmt.Sprintf("Admins: %d. ", len(g.Admins)))
	}
	return sb.String()
}
