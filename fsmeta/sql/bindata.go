// Code generated by go-bindata.
// sources:
// 001_initial_fsmeta.down.sql
// 001_initial_fsmeta.up.sql
// bindata.go
// gen.go
// DO NOT EDIT!

package sql

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func bindataRead(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type asset struct {
	bytes []byte
	info  os.FileInfo
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (fi bindataFileInfo) Name() string {
	return fi.name
}
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}
func (fi bindataFileInfo) IsDir() bool {
	return false
}
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var __001_initial_fsmetaDownSql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x72\x72\x75\xf7\xf4\xb3\xe6\xe2\x72\x09\xf2\x0f\x50\x08\x71\x74\xf2\x71\x55\xf0\x74\x53\x70\x8d\xf0\x0c\x0e\x09\x56\x48\x2b\xce\x4d\x2d\x49\x8c\x4f\xcb\xcc\x49\x2d\xb6\xc6\xaf\x24\x3f\x27\x25\xb5\xa8\xd8\x9a\x8b\xcb\xd9\xdf\xd7\xd7\x33\xc4\x1a\x10\x00\x00\xff\xff\x99\x7b\x05\xfa\x58\x00\x00\x00")

func _001_initial_fsmetaDownSqlBytes() ([]byte, error) {
	return bindataRead(
		__001_initial_fsmetaDownSql,
		"001_initial_fsmeta.down.sql",
	)
}

func _001_initial_fsmetaDownSql() (*asset, error) {
	bytes, err := _001_initial_fsmetaDownSqlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "001_initial_fsmeta.down.sql", size: 88, mode: os.FileMode(420), modTime: time.Unix(1611257883, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var __001_initial_fsmetaUpSql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xa4\x52\x4f\xab\xe2\x30\x10\xbf\xf7\x53\xcc\x4d\x05\x0f\x7b\xd6\x93\xee\x66\x97\xc2\x5a\x79\xcf\x0a\xde\x42\x30\x53\x1d\x4c\xd2\x92\x4c\x79\xea\xa7\x7f\xf4\x9f\x62\x55\x14\xde\x1c\xdb\xf9\xfd\x9d\xcc\xc5\xbf\x38\x99\x46\xd1\xef\x4f\x31\x4b\x05\xa4\xb3\xf9\x7f\x01\xf1\x5f\x48\x96\x29\x88\x4d\xbc\x4a\x57\x90\x05\x8b\xac\x64\x96\x1b\x8d\x3e\x44\xc3\x08\x00\x80\x34\x00\x04\xf4\xa4\x0c\xb8\x9c\xc1\x95\xc6\xd4\x3f\xaa\xd9\xe6\x2e\xb0\x57\xe4\xb8\x07\x96\xc5\x01\x0a\x4f\x56\xf9\x13\x1c\xf0\x34\xae\x11\x85\xe2\x3d\x30\x1e\x19\xe0\x4a\x35\xba\x7a\x5a\x27\xf1\xc7\x5a\x40\x9c\xfc\x11\x9b\x3b\x3e\xc5\x7b\x59\x92\xd3\x78\xac\xb9\x96\x49\x6f\x03\x86\xd5\xca\xe8\xbd\x84\x64\xf0\x26\xdf\x65\xda\xa0\xf7\xf3\x4e\xf4\x8a\xf5\x61\xf0\xc6\xa2\x6c\xa5\xc8\x31\xee\xd0\xff\x40\xa3\xd7\x0d\x69\x99\x1d\xc0\x63\x86\x1e\xdd\x16\x43\xaf\x99\xd6\x03\x19\x74\xca\x62\xc3\xdc\x5e\xe1\xb9\x87\x06\x54\x16\x26\x57\x1a\xdb\x8a\x98\x2c\x06\x56\xb6\x80\x2f\xaa\x2e\x49\x16\xe1\x9c\x3b\xec\x81\x6a\x8f\x74\x6e\x95\xba\xb4\x1a\x33\x55\x1a\x86\x5f\x8f\x95\x90\xd5\xee\xea\xa2\xb3\xd7\x81\x06\x83\xc9\xa4\xfe\x76\x0b\x32\x2a\xb0\xb4\xb9\xa6\x8c\x50\xbf\xb6\xf7\xf2\xad\x35\xe5\x76\xc7\x92\x5d\x65\x4f\xde\x5d\xb5\x0d\xc3\xcb\xfa\xf8\x52\x71\x2d\xb3\x5c\x2c\xe2\x74\xfa\x1d\x00\x00\xff\xff\x9e\xc2\xf1\xf4\x76\x03\x00\x00")

func _001_initial_fsmetaUpSqlBytes() ([]byte, error) {
	return bindataRead(
		__001_initial_fsmetaUpSql,
		"001_initial_fsmeta.up.sql",
	)
}

func _001_initial_fsmetaUpSql() (*asset, error) {
	bytes, err := _001_initial_fsmetaUpSqlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "001_initial_fsmeta.up.sql", size: 886, mode: os.FileMode(420), modTime: time.Unix(1611260677, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _bindataGo = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x01\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00")

func bindataGoBytes() ([]byte, error) {
	return bindataRead(
		_bindataGo,
		"bindata.go",
	)
}

func bindataGo() (*asset, error) {
	bytes, err := bindataGoBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "bindata.go", size: 4096, mode: os.FileMode(420), modTime: time.Unix(1611260681, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _genGo = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x2a\x48\x4c\xce\x4e\x4c\x4f\x55\x28\x2e\xcc\xe1\xe2\xd2\xd7\x4f\xcf\xb7\x4a\x4f\xcd\x4b\x2d\x4a\x2c\x49\x55\x48\xcf\xd7\x4d\xca\xcc\x4b\x49\x2c\x49\x54\xd0\x2d\xc8\x4e\x07\x29\x51\xd0\xe3\x02\x04\x00\x00\xff\xff\x94\x1c\xa4\x24\x31\x00\x00\x00")

func genGoBytes() ([]byte, error) {
	return bindataRead(
		_genGo,
		"gen.go",
	)
}

func genGo() (*asset, error) {
	bytes, err := genGoBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "gen.go", size: 49, mode: os.FileMode(420), modTime: time.Unix(1611257883, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"001_initial_fsmeta.down.sql": _001_initial_fsmetaDownSql,
	"001_initial_fsmeta.up.sql":   _001_initial_fsmetaUpSql,
	"bindata.go":                  bindataGo,
	"gen.go":                      genGo,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}

var _bintree = &bintree{nil, map[string]*bintree{
	"001_initial_fsmeta.down.sql": &bintree{_001_initial_fsmetaDownSql, map[string]*bintree{}},
	"001_initial_fsmeta.up.sql":   &bintree{_001_initial_fsmetaUpSql, map[string]*bintree{}},
	"bindata.go":                  &bintree{bindataGo, map[string]*bintree{}},
	"gen.go":                      &bintree{genGo, map[string]*bintree{}},
}}

// RestoreAsset restores an asset under the given directory
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	err = os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
	if err != nil {
		return err
	}
	return nil
}

// RestoreAssets restores an asset under the given directory recursively
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}