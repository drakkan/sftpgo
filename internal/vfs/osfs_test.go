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
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func newTestOsFs(t *testing.T) (*OsFs, string, string) {
	t.Helper()

	baseDir := t.TempDir()
	rootDir := filepath.Join(baseDir, "root")
	outsideDir := filepath.Join(baseDir, "outside")
	if err := os.MkdirAll(filepath.Join(rootDir, "drop"), os.ModePerm); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outsideDir, os.ModePerm); err != nil {
		t.Fatal(err)
	}

	return NewOsFs("test", rootDir, "", nil).(*OsFs), rootDir, outsideDir
}

func TestOsFsCreateRejectsDanglingSymlinkOutsideRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires extra privileges on Windows")
	}

	fs, rootDir, outsideDir := newTestOsFs(t)
	linkPath := filepath.Join(rootDir, "drop", "link")
	outsideTarget := filepath.Join(outsideDir, "created.txt")
	if err := os.Symlink("../../outside/created.txt", linkPath); err != nil {
		t.Fatal(err)
	}

	f, w, cancelFn, err := fs.Create(linkPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0)
	if err == nil {
		if f != nil {
			_ = f.Close()
		}
		if w != nil {
			_ = w.Close()
		}
		if cancelFn != nil {
			cancelFn()
		}
		t.Fatal("expected write through dangling symlink outside root to fail")
	}
	if _, statErr := os.Stat(outsideTarget); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("outside target was created, stat err: %v", statErr)
	}
}

func TestOsFsCreateAllowsDanglingSymlinkInsideRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires extra privileges on Windows")
	}

	fs, rootDir, _ := newTestOsFs(t)
	linkPath := filepath.Join(rootDir, "drop", "link")
	insideTarget := filepath.Join(rootDir, "created.txt")
	if err := os.Symlink("../created.txt", linkPath); err != nil {
		t.Fatal(err)
	}

	f, _, _, err := fs.Create(linkPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(insideTarget); err != nil {
		t.Fatal(err)
	}
}

func TestOsFsCreateAllowsAtomicUploadTempPath(t *testing.T) {
	fs, _, _ := newTestOsFs(t)
	oldTempPath := tempPath
	SetTempPath(t.TempDir())
	t.Cleanup(func() {
		SetTempPath(oldTempPath)
	})

	filePath := fs.GetAtomicUploadPath(filepath.Join(fs.rootDir, "file.txt"))
	f, _, _, err := fs.Create(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filePath); err != nil {
		t.Fatal(err)
	}
}

func TestOsFsRenameRejectsSymlinkedParentOutsideRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires extra privileges on Windows")
	}

	fs, rootDir, outsideDir := newTestOsFs(t)
	source := filepath.Join(filepath.Dir(rootDir), "upload.tmp")
	outsideParent := filepath.Join(outsideDir, "parent")
	if err := os.MkdirAll(outsideParent, os.ModePerm); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("payload"), os.ModePerm); err != nil {
		t.Fatal(err)
	}

	targetParent := filepath.Join(rootDir, "drop")
	if err := os.RemoveAll(targetParent); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../outside/parent", targetParent); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(targetParent, "created.txt")

	if _, _, err := fs.Rename(source, target, 0); err == nil {
		t.Fatal("expected rename through symlinked parent outside root to fail")
	}
	if _, err := os.Stat(filepath.Join(outsideParent, "created.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("outside target was created, stat err: %v", err)
	}
	if _, err := os.Stat(source); err != nil {
		t.Fatalf("source should remain after rejected rename: %v", err)
	}
}
