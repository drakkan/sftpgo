// Copyright (C) 2019 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

package vfs

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestOsFsReadDirRejectsRegularFile(t *testing.T) {
	root := t.TempDir()
	filePath := filepath.Join(root, "file.mp4")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	fs := NewOsFs("test-conn", root, "", nil)
	defer fs.Close()

	lister, err := fs.ReadDir(filePath)
	if err == nil {
		_ = lister.Close()
		t.Fatal("expected ReadDir on a regular file to fail")
	}
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) {
		t.Fatalf("expected *os.PathError, got %T: %v", err, err)
	}
	if !errors.Is(pathErr.Err, syscall.ENOTDIR) {
		t.Fatalf("expected ENOTDIR, got %v", pathErr.Err)
	}

	dirLister, err := fs.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir on directory: %v", err)
	}
	defer dirLister.Close()
	entries, err := dirLister.Next(10)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("Next: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "file.mp4" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
}
