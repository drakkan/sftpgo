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

package dataprovider

import (
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sftpgo/sdk"

	"github.com/xrogers/gonas/v2/internal/logger"
	"github.com/xrogers/gonas/v2/internal/util"
	"github.com/xrogers/gonas/v2/internal/vfs"
)

var (
	namesFoldPlatform   = runtime.GOOS == "windows" || runtime.GOOS == "darwin"
	identityForAllNames = runtime.GOOS == "darwin"
	findSameEntry       = vfs.FindSameEntry
	lastKeyPathWarning  atomic.Int64
)

func (u *User) hasPathKeys() bool {
	return len(u.Permissions) > 1 || len(u.Filters.FilePatterns) > 0
}

func (u *User) keyComponentsBelow(dir string) []string {
	var names []string
	add := func(key string) {
		var rest string
		switch {
		case dir == "/":
			rest = key[1:]
		case len(key) > len(dir) && key[len(dir)] == '/' && strings.HasPrefix(key, dir):
			rest = key[len(dir)+1:]
		default:
			return
		}
		name, _, _ := strings.Cut(rest, "/")
		if name != "" && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	for key := range u.Permissions {
		add(key)
	}
	for idx := range u.Filters.FilePatterns {
		add(u.Filters.FilePatterns[idx].Path)
	}
	return names
}

func isLocalStorage(provider sdk.FilesystemProvider) bool {
	return provider == sdk.LocalFilesystemProvider || provider == sdk.CryptedFilesystemProvider
}

func (u *User) keyPath(virtualPath string) (string, bool) {
	if !namesFoldPlatform || virtualPath == "" || virtualPath == "/" || !u.hasPathKeys() {
		return virtualPath, true
	}
	components := strings.Split(virtualPath[1:], "/")
	canonical, requested := "/", "/"
	for i, c := range components {
		keys := u.keyComponentsBelow(canonical)
		if len(keys) == 0 {
			return joinPath(canonical, components[i:]), true
		}
		match := c
		if !slices.Contains(keys, c) {
			var ok bool
			match, ok = u.matchKeyComponent(keys, canonical, requested, c)
			if !ok {
				return virtualPath, false
			}
			if match == "" {
				return joinPath(canonical, components[i:]), true
			}
		}
		nextCanonical, nextRequested := path.Join(canonical, match), path.Join(requested, c)
		if nextCanonical != nextRequested {
			if mount, requestMount := u.MountPathFor(nextCanonical), u.MountPathFor(nextRequested); mount != requestMount {
				warnKeyPath("user %q: %q reaches the directory beneath the mount point %q",
					u.Username, nextRequested, mount)
				return virtualPath, false
			}
		}
		canonical, requested = nextCanonical, nextRequested
	}
	return canonical, true
}

func namesNeedIdentity(a, b string) bool {
	if identityForAllNames {
		return !util.IsASCII(a) || !util.IsASCII(b)
	}
	return !util.IsASCII(a) && !util.IsASCII(b)
}

func keyCandidates(keys []string, c string) (string, []string) {
	asciiRequest := util.IsASCII(c)
	var folded string
	var candidates []string
	for _, key := range keys {
		switch {
		case asciiRequest && util.IsASCII(key):
			if util.EqualFoldASCII(key, c) && (folded == "" || key < folded) {
				folded = key
			}
		case namesNeedIdentity(key, c):
			candidates = append(candidates, key)
		}
	}
	return folded, candidates
}

func (u *User) RenameTargetUndecided(virtualPath string) bool {
	if !namesFoldPlatform || virtualPath == "/" || !u.hasPathKeys() {
		return false
	}
	dir, ok := u.keyPath(path.Dir(virtualPath))
	if !ok {
		return true
	}
	keys := u.keyComponentsBelow(dir)
	name := path.Base(virtualPath)
	if len(keys) == 0 || slices.Contains(keys, name) {
		return false
	}
	if folded, candidates := keyCandidates(keys, name); folded != "" || len(candidates) == 0 {
		return false
	}
	provider, _, mountPath := u.storageAt(virtualPath)
	return isLocalStorage(provider) && mountPath != virtualPath
}

func (u *User) matchKeyComponent(keys []string, canonical, requested, c string) (string, bool) {
	folded, candidates := keyCandidates(keys, c)
	if folded == "" && len(candidates) == 0 {
		return "", true
	}
	requestPath := path.Join(requested, c)
	provider, rootDir, mountPath := u.storageAt(requestPath)
	// a mount point is reached by its exact name, and its siblings are on another storage
	if !isLocalStorage(provider) || mountPath == requestPath {
		return "", true
	}
	if folded != "" {
		return folded, true
	}
	rels := make([]string, 0, len(candidates))
	for _, name := range candidates {
		rels = append(rels, storageRel(path.Join(requested, name), mountPath))
	}
	found, err := findSameEntry(rootDir, storageRel(requestPath, mountPath), rels)
	if err != nil {
		warnKeyPath("user %q: unable to compare %q with the keys below %q: %v", u.Username, requestPath, canonical, err)
		return "", false
	}
	if found < 0 {
		return "", true
	}
	return candidates[found], true
}

func warnKeyPath(format string, v ...any) {
	now := time.Now().Unix()
	last := lastKeyPathWarning.Load()
	if now-last < 60 || !lastKeyPathWarning.CompareAndSwap(last, now) {
		return
	}
	logger.Warn(logSender, "", format, v...)
}

func (u *User) storageAt(virtualPath string) (sdk.FilesystemProvider, string, string) {
	if folder, err := u.GetVirtualFolderForPath(virtualPath); err == nil {
		return folder.FsConfig.Provider, folder.MappedPath, folder.VirtualPath
	}
	return u.FsConfig.Provider, u.GetHomeDir(), ""
}

// MountPathFor returns the mount point serving virtualPath, empty for the home
// directory.
func (u *User) MountPathFor(virtualPath string) string {
	if len(u.VirtualFolders) == 0 {
		return ""
	}
	for _, dir := range util.GetDirsForVirtualPath(virtualPath) {
		for idx := range u.VirtualFolders {
			if u.VirtualFolders[idx].VirtualPath == dir {
				return dir
			}
		}
	}
	return ""
}

// FoldsNamesAt reports whether virtualPath is served by local storage on Windows or
// macOS.
func (u *User) FoldsNamesAt(virtualPath string) bool {
	if !namesFoldPlatform {
		return false
	}
	provider, _, _ := u.storageAt(virtualPath)
	return isLocalStorage(provider)
}

func storageRel(virtualPath, mountPath string) string {
	rel := strings.TrimPrefix(strings.TrimPrefix(virtualPath, mountPath), "/")
	if rel == "" {
		return "."
	}
	return filepath.FromSlash(rel)
}

func joinPath(dir string, components []string) string {
	return path.Join(append([]string{dir}, components...)...)
}

func foldASCII(s string) string {
	for i := range len(s) {
		if s[i] >= 'A' && s[i] <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

func matchPermissionKey(key, dir string, fold bool) (bool, error) {
	if !fold || !strings.ContainsAny(key, `*?[\`) {
		return path.Match(key, dir)
	}
	literal := key[:strings.IndexAny(key, `*?[\`)]
	if len(dir) < len(literal) || !util.EqualFoldASCII(literal, dir[:len(literal)]) {
		return false, nil
	}
	return path.Match(foldASCII(key), foldASCII(dir))
}
