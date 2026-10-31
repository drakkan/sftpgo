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

package vfs

import (
	"errors"
	iofs "io/fs"
	"os"
)

// SameFile reports whether name in fs and otherName in otherFs reach the same file,
// following a link in the last component. Local and encrypted local backends only,
// the others return ErrVfsUnsupported.
func SameFile(fs Fs, name string, otherFs Fs, otherName string) (bool, error) {
	return sameLocalEntry(fs, name, otherFs, otherName, true)
}

// SameEntry is SameFile without following a link in the last component.
func SameEntry(fs Fs, name string, otherFs Fs, otherName string) (bool, error) {
	return sameLocalEntry(fs, name, otherFs, otherName, false)
}

func sameLocalEntry(fs Fs, name string, otherFs Fs, otherName string, followLinks bool) (bool, error) {
	localFs, ok := localOsFs(fs)
	if !ok {
		return false, ErrVfsUnsupported
	}
	otherLocalFs, ok := localOsFs(otherFs)
	if !ok {
		return false, ErrVfsUnsupported
	}
	root, rel, err := localFs.toRootRelative(name)
	if err != nil {
		return false, err
	}
	otherRoot, otherRel, err := otherLocalFs.toRootRelative(otherName)
	if err != nil {
		return false, err
	}
	return sameEntry(root, rel, otherRoot, otherRel, followLinks)
}

func localOsFs(fs Fs) (*OsFs, bool) {
	switch v := fs.(type) {
	case *OsFs:
		return v, true
	case *CryptFs:
		return v.OsFs, true
	}
	return nil, false
}

// FindSameEntry returns the index of the first of names that is the same entry as
// name, -1 if none, without following a link in the last component. Paths are
// relative to rootDir.
func FindSameEntry(rootDir, name string, names []string) (int, error) {
	root, err := os.OpenRoot(rootDir)
	if err != nil {
		if errors.Is(err, iofs.ErrNotExist) {
			return -1, nil
		}
		return -1, err
	}
	defer root.Close()

	return findSameEntry(root, name, names)
}
