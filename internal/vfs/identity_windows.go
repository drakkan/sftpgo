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
	"encoding/binary"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type fileIDInfo struct {
	VolumeSerialNumber uint64
	FileID             [16]byte
}

type fileID struct {
	volume uint64
	id     [16]byte
}

func (f fileID) isZero() bool {
	return f.id == [16]byte{}
}

func openForFileID(root *os.Root, name string, followLinks bool) (*os.File, error) {
	flag := os.O_RDONLY
	if !followLinks {
		flag |= syscall.FILE_FLAG_OPEN_REPARSE_POINT
	}
	return root.OpenFile(name, flag, 0)
}

func readFileIDInfo(h windows.Handle) (fileID, error) {
	var info fileIDInfo
	err := windows.GetFileInformationByHandleEx(h, windows.FileIdInfo, (*byte)(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)))
	if err != nil {
		return fileID{}, err
	}
	return fileID{volume: info.VolumeSerialNumber, id: info.FileID}, nil
}

func readFileIndex(h windows.Handle) (fileID, error) {
	var bi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &bi); err != nil {
		return fileID{}, err
	}
	id := fileID{volume: uint64(bi.VolumeSerialNumber)}
	binary.LittleEndian.PutUint32(id.id[0:], bi.FileIndexLow)
	binary.LittleEndian.PutUint32(id.id[4:], bi.FileIndexHigh)
	return id, nil
}

func readFileIDs(hA, hB windows.Handle) (fileID, fileID, error) {
	idA, errA := readFileIDInfo(hA)
	idB, errB := readFileIDInfo(hB)
	if errA == nil && errB == nil {
		return idA, idB, nil
	}
	idA, err := readFileIndex(hA)
	if err != nil {
		return fileID{}, fileID{}, err
	}
	idB, err = readFileIndex(hB)
	if err != nil {
		return fileID{}, fileID{}, err
	}
	return idA, idB, nil
}

func sameEntry(rootA *os.Root, nameA string, rootB *os.Root, nameB string, followLinks bool) (bool, error) {
	fA, err := openForFileID(rootA, nameA, followLinks)
	if err != nil {
		return false, err
	}
	defer fA.Close()

	fB, err := openForFileID(rootB, nameB, followLinks)
	if err != nil {
		return false, err
	}
	defer fB.Close()

	return sameOpened(fA, fB)
}

func sameOpened(fA, fB *os.File) (bool, error) {
	idA, idB, err := readFileIDs(windows.Handle(fA.Fd()), windows.Handle(fB.Fd()))
	if err != nil {
		return false, err
	}
	if idA.isZero() || idB.isZero() {
		return false, ErrVfsUnsupported
	}
	return idA == idB, nil
}

func findSameEntry(root *os.Root, name string, names []string) (int, error) {
	f, err := openForFileID(root, name, false)
	if err != nil {
		if isMissingName(err) {
			return -1, nil
		}
		return -1, err
	}
	defer f.Close()

	var firstErr error
	for idx, other := range names {
		same, err := sameAsOpened(f, root, other)
		if err != nil {
			if !isMissingName(err) && firstErr == nil {
				firstErr = err
			}
			continue
		}
		if same {
			return idx, nil
		}
	}
	return -1, firstErr
}

func sameAsOpened(f *os.File, root *os.Root, name string) (bool, error) {
	other, err := openForFileID(root, name, false)
	if err != nil {
		return false, err
	}
	defer other.Close()

	return sameOpened(f, other)
}
