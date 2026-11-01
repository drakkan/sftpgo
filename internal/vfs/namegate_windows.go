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
	"strings"
	"syscall"
	"unicode/utf8"

	"golang.org/x/sys/windows"

	"github.com/xrogers/gonas/v2/internal/util"
)

const finalPathNormalizedNoVolume = 0x4

func checkRootRelativeName(root *os.Root, rel string) error {
	components := strings.Split(rel, `\`)
	for _, c := range components {
		if strings.HasSuffix(c, ".") || strings.HasSuffix(c, " ") {
			return &invalidNameError{name: rel}
		}
	}
	for idx, c := range components {
		if !hasShortNameShape(c) {
			continue
		}
		if err := checkLongName(root, strings.Join(components[:idx+1], `\`), c); err != nil {
			return err
		}
	}
	return nil
}

func hasShortNameShape(name string) bool {
	base, ext, _ := strings.Cut(name, ".")
	if utf8.RuneCountInString(base) > 8 || utf8.RuneCountInString(ext) > 3 || strings.Contains(ext, ".") {
		return false
	}
	for {
		idx := strings.IndexByte(base, '~')
		if idx < 0 || idx == len(base)-1 {
			return false
		}
		if c := base[idx+1]; (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return true
		}
		base = base[idx+1:]
	}
}

func checkLongName(root *os.Root, prefix, component string) error {
	f, err := root.OpenFile(prefix, os.O_RDONLY|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		if errors.Is(err, iofs.ErrNotExist) {
			return nil
		}
		return err
	}
	defer f.Close()

	longName, err := finalName(windows.Handle(f.Fd()))
	if err != nil || !util.EqualFoldASCII(longName, component) {
		return &iofs.PathError{Op: "resolve", Path: prefix, Err: iofs.ErrNotExist}
	}
	return nil
}

func finalName(h windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_PATH)
	for {
		n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), finalPathNormalizedNoVolume)
		if err != nil {
			return "", err
		}
		if n < uint32(len(buf)) {
			p := windows.UTF16ToString(buf[:n])
			return p[strings.LastIndexByte(p, '\\')+1:], nil
		}
		buf = make([]uint16, n)
	}
}
