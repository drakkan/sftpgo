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

//go:build !windows

package vfs

import "os"

func sameEntry(rootA *os.Root, nameA string, rootB *os.Root, nameB string, followLinks bool) (bool, error) {
	stat := (*os.Root).Lstat
	if followLinks {
		stat = (*os.Root).Stat
	}
	infoA, err := stat(rootA, nameA)
	if err != nil {
		return false, err
	}
	infoB, err := stat(rootB, nameB)
	if err != nil {
		return false, err
	}
	return os.SameFile(infoA, infoB), nil
}

func findSameEntry(root *os.Root, name string, names []string) (int, error) {
	info, err := root.Lstat(name)
	if err != nil {
		if isMissingName(err) {
			return -1, nil
		}
		return -1, err
	}
	var firstErr error
	for idx, other := range names {
		otherInfo, err := root.Lstat(other)
		if err != nil {
			if !isMissingName(err) && firstErr == nil {
				firstErr = err
			}
			continue
		}
		if os.SameFile(info, otherInfo) {
			return idx, nil
		}
	}
	return -1, firstErr
}
