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

package httpd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"image"
	"image/jpeg"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	// Register the image decoders used to generate thumbnails.
	_ "image/gif"
	_ "image/png"

	"golang.org/x/image/draw"
	_ "golang.org/x/image/bmp"
	_ "golang.org/x/image/webp"

	"github.com/drakkan/sftpgo/v2/internal/logger"
)

const (
	// thumbnailMaxEdge is the size, in pixels, of the longest edge of a
	// generated thumbnail.
	thumbnailMaxEdge = 200
	// thumbnailJPEGQuality is the JPEG quality used when encoding thumbnails.
	thumbnailJPEGQuality = 80
)

// imageThumbExtensions and videoThumbExtensions are the allow-lists of source
// file extensions for which a thumbnail can be generated.
var (
	imageThumbExtensions = map[string]bool{
		".jpg": true, ".jpeg": true, ".png": true, ".gif": true,
		".webp": true, ".bmp": true,
	}
	videoThumbExtensions = map[string]bool{
		".mp4": true, ".mov": true, ".mkv": true, ".webm": true,
		".avi": true, ".m4v": true,
	}
)

// thumbnailer holds the resolved thumbnail configuration and cache state. It is
// safe for concurrent use. A single package-level instance is configured by
// initThumbnailer during HTTP server initialization.
type thumbnailer struct {
	enabled       bool
	cacheDir      string
	maxSourceSize int64 // bytes; 0 means no limit
	maxCacheSize  int64 // bytes; 0 means no limit
	ffmpegPath    string
	evictMu       sync.Mutex
}

var thumbs = &thumbnailer{}

// initThumbnailer resolves the thumbnails configuration into the package-level
// thumbs instance. It never fails hard: on any setup problem thumbnails are
// simply disabled and the WebClient falls back to generic icons.
func initThumbnailer(cfg ThumbnailsConfig, configDir string) {
	t := &thumbnailer{enabled: cfg.Enabled}
	if !cfg.Enabled {
		thumbs = t
		logger.Info(logSender, "", "WebClient thumbnails are disabled")
		return
	}

	cacheDir := cfg.CacheDir
	if cacheDir == "" {
		cacheDir = filepath.Join(os.TempDir(), "sftpgo-thumbnails")
	} else if !filepath.IsAbs(cacheDir) {
		cacheDir = filepath.Join(configDir, cacheDir)
	}
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		logger.Warn(logSender, "", "unable to create thumbnails cache dir %q, thumbnails disabled: %v", cacheDir, err)
		thumbs = &thumbnailer{enabled: false}
		return
	}
	t.cacheDir = cacheDir

	if cfg.MaxSourceSize > 0 {
		t.maxSourceSize = int64(cfg.MaxSourceSize) * 1024 * 1024
	}
	if cfg.CacheMaxSize > 0 {
		t.maxCacheSize = int64(cfg.CacheMaxSize) * 1024 * 1024
	}

	ffmpegPath := cfg.FFmpegPath
	if ffmpegPath == "" {
		if p, err := exec.LookPath("ffmpeg"); err == nil {
			ffmpegPath = p
		}
	} else if _, err := os.Stat(ffmpegPath); err != nil {
		logger.Warn(logSender, "", "configured ffmpeg path %q is not usable, video thumbnails disabled: %v", ffmpegPath, err)
		ffmpegPath = ""
	}
	t.ffmpegPath = ffmpegPath

	thumbs = t
	logger.Info(logSender, "", "WebClient thumbnails enabled, cache dir %q, video thumbnails available: %v",
		cacheDir, ffmpegPath != "")
}

// thumbnailURLForUser returns the WebClient thumbnail endpoint if thumbnails are
// enabled, or an empty string otherwise so the frontend can skip requesting them.
func thumbnailURLForUser() string {
	if thumbs != nil && thumbs.enabled {
		return webClientThumbnailPath
	}
	return ""
}

// canThumbnail reports whether a thumbnail can be produced for the given file
// name based on its extension and the current configuration.
func (t *thumbnailer) canThumbnail(name string) bool {
	if t == nil || !t.enabled {
		return false
	}
	ext := strings.ToLower(path.Ext(name))
	if imageThumbExtensions[ext] {
		return true
	}
	if videoThumbExtensions[ext] {
		return t.ffmpegPath != ""
	}
	return false
}

func (t *thumbnailer) isVideo(name string) bool {
	return videoThumbExtensions[strings.ToLower(path.Ext(name))]
}

// readLimit returns the maximum number of source bytes to read when generating a
// thumbnail. It falls back to a sane default when no explicit limit is set so an
// unbounded source can never exhaust memory.
func (t *thumbnailer) readLimit() int64 {
	if t.maxSourceSize > 0 {
		return t.maxSourceSize
	}
	return 100 * 1024 * 1024
}

// cacheKey derives a stable cache key from the tuple that uniquely identifies a
// thumbnail: the owning user, the virtual path, and the source file's mod time
// and size. Any change to the source produces a new key (and a new cache entry).
func (t *thumbnailer) cacheKey(username, name string, modTime time.Time, size int64) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%d\x00%d", username, name, modTime.UnixNano(), size)
	return hex.EncodeToString(h.Sum(nil))
}

func (t *thumbnailer) cachePath(key string) string {
	return filepath.Join(t.cacheDir, key+".jpg")
}

// generateFromImage decodes an image from r and returns a JPEG-encoded
// thumbnail scaled so its longest edge is at most thumbnailMaxEdge.
func (t *thumbnailer) generateFromImage(r io.Reader) ([]byte, error) {
	src, _, err := image.Decode(r)
	if err != nil {
		return nil, fmt.Errorf("unable to decode image: %w", err)
	}
	return encodeThumbnail(src)
}

// generateFromVideo writes the source video to a temporary file and uses ffmpeg
// to extract a single frame near the start, returning it as a JPEG thumbnail.
func (t *thumbnailer) generateFromVideo(r io.Reader, ext string) ([]byte, error) {
	if t.ffmpegPath == "" {
		return nil, fmt.Errorf("ffmpeg not available")
	}
	tmpIn, err := os.CreateTemp(t.cacheDir, "thumbsrc-*"+ext)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpIn.Name())
	if _, err := io.Copy(tmpIn, r); err != nil {
		tmpIn.Close()
		return nil, err
	}
	tmpIn.Close()

	tmpOut := tmpIn.Name() + ".jpg"
	defer os.Remove(tmpOut)

	// Seek 1s in, grab one frame, scale to the target width keeping aspect ratio.
	cmd := exec.Command(t.ffmpegPath, "-y", "-ss", "00:00:01", "-i", tmpIn.Name(),
		"-frames:v", "1", "-vf", fmt.Sprintf("scale=%d:-1", thumbnailMaxEdge),
		"-f", "image2", tmpOut)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("ffmpeg failed: %w (%s)", err, string(out))
	}
	// Re-encode through the shared path so the output size/format is consistent
	// and to handle the (rare) case ffmpeg produced an oversized frame.
	f, err := os.Open(tmpOut)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	src, _, err := image.Decode(f)
	if err != nil {
		return nil, fmt.Errorf("unable to decode ffmpeg frame: %w", err)
	}
	return encodeThumbnail(src)
}

// encodeThumbnail scales src to fit within thumbnailMaxEdge and JPEG-encodes it.
func encodeThumbnail(src image.Image) ([]byte, error) {
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	if w <= 0 || h <= 0 {
		return nil, fmt.Errorf("invalid image bounds")
	}
	nw, nh := w, h
	if w >= h && w > thumbnailMaxEdge {
		nw = thumbnailMaxEdge
		nh = h * thumbnailMaxEdge / w
	} else if h > w && h > thumbnailMaxEdge {
		nh = thumbnailMaxEdge
		nw = w * thumbnailMaxEdge / h
	}
	if nw < 1 {
		nw = 1
	}
	if nh < 1 {
		nh = 1
	}
	dst := image.NewRGBA(image.Rect(0, 0, nw, nh))
	draw.CatmullRom.Scale(dst, dst.Bounds(), src, b, draw.Over, nil)

	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, dst, &jpeg.Options{Quality: thumbnailJPEGQuality}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// store atomically writes the thumbnail bytes to the cache and triggers a
// best-effort eviction if the cache size limit is configured.
func (t *thumbnailer) store(key string, data []byte) {
	dst := t.cachePath(key)
	tmp, err := os.CreateTemp(t.cacheDir, "thumb-*.tmp")
	if err != nil {
		logger.Debug(logSender, "", "unable to create thumbnail temp file: %v", err)
		return
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return
	}
	tmp.Close()
	if err := os.Rename(tmpName, dst); err != nil {
		os.Remove(tmpName)
		return
	}
	if t.maxCacheSize > 0 {
		go t.evict()
	}
}

// evict removes the oldest cached thumbnails until the total cache size is below
// the configured limit. It is best-effort and serialized by evictMu.
func (t *thumbnailer) evict() {
	if !t.evictMu.TryLock() {
		return
	}
	defer t.evictMu.Unlock()

	entries, err := os.ReadDir(t.cacheDir)
	if err != nil {
		return
	}
	type fileInfo struct {
		path    string
		size    int64
		modTime time.Time
	}
	files := make([]fileInfo, 0, len(entries))
	var total int64
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jpg") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, fileInfo{filepath.Join(t.cacheDir, e.Name()), info.Size(), info.ModTime()})
		total += info.Size()
	}
	if total <= t.maxCacheSize {
		return
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].modTime.Before(files[j].modTime)
	})
	for _, f := range files {
		if total <= t.maxCacheSize {
			break
		}
		if err := os.Remove(f.path); err == nil {
			total -= f.size
		}
	}
}
