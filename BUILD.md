# SFTPGo Özel Build ve Deployment Kılavuzu

Bu doküman, özelleştirilmiş SFTPGo'nun `.deb` paketi oluşturma ve sunucuya kurulum adımlarını açıklar.

---

## Gereksinimler

- macOS (Apple Silicon / arm64)
- Go 1.25+ (`go version` ile kontrol edin)
- Zig (`brew install zig`) — SQLite için C cross-compiler olarak kullanılır
- Docker Desktop (çalışıyor olmalı) — paketleme için

> ⚠️ **Önemli:** `CGO_ENABLED=0` ile derlenen binary SQLite'sız gelir (`-sqlite`).
> Sunucu SQLite kullandığı için mutlaka `zig cc` ile CGO etkin derleme yapılmalıdır.

---

## 1. Zig Kurulumu (Bir kez yapılır)

```bash
brew install zig
zig version  # doğrulama
```

---

## 2. Linux Binary Derleme — SQLite Destekli (Mac'te)

```bash
cd /Users/orhangazibasli/Desktop/Paylasim/Project/sftpgo

CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
  CC="zig cc -target x86_64-linux-musl" \
  CXX="zig c++ -target x86_64-linux-musl" \
  go build -ldflags='-s -w -extldflags "-static"' -o sftpgo .
```

Derleme sonrası doğrulama:
```bash
file sftpgo
# "ELF 64-bit LSB executable, x86-64, statically linked" çıkmalı
```

---

## 3. Döküman Dosyalarını Üretme (Mac'te)

Build script bash completion ve man page gerektirir. Bunları Mac'te üretiyoruz:

```bash
# Geçici darwin binary oluştur
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 \
  go build -ldflags='-s -w' -o sftpgo_darwin .

# Klasörleri oluştur ve dosyaları üret
mkdir -p output/bash_completion output/man/man1
./sftpgo_darwin gen completion bash > output/bash_completion/sftpgo
./sftpgo_darwin gen man -d output/man/man1

# Geçici darwin binary'i sil
rm sftpgo_darwin
```

> Docs klasörü `output/` zaten varsa bu adımı tekrar yapmaya gerek yok.

---

## 4. Önceki Build Çıktısını Temizle

```bash
rm -rf pkgs/dist
```

---

## 5. .deb Paketi Oluşturma (Docker ile)

```bash
docker run --rm \
  --platform linux/amd64 \
  -v $(pwd):/sftpgo \
  -w /sftpgo/pkgs \
  -e NFPM_ARCH=amd64 \
  -e SFTPGO_VERSION=2.6.5-custom \
  ubuntu:22.04 \
  bash -c "apt-get update -q && apt-get install -y git curl && bash build.sh"
```

Çıktı dosyası:
```
pkgs/dist/deb/sftpgo_2.6.5~custom-1_amd64.deb
```

---

## 6. Sunucuya Kurulum (Güncelleme)

```bash
# .deb dosyasını sunucuya kopyala
scp pkgs/dist/deb/sftpgo_2.6.5~custom-1_amd64.deb root@10.35.40.7:/tmp/

# Sunucuda durdur, kur, başlat
ssh root@10.35.40.7 "systemctl stop sftpgo && \
  dpkg -i /tmp/sftpgo_2.6.5~custom-1_amd64.deb && \
  systemctl start sftpgo && \
  systemctl status sftpgo"
```

> **Not:** `dpkg -i` mevcut `/etc/sftpgo/sftpgo.json` config dosyasını korur. Ayarlarınız kaybolmaz.

---

## 7. Sorun Giderme

| Hata | Çözüm |
|------|-------|
| `SQLite disabled at build time` | `zig cc` ile CGO_ENABLED=1 derleme yapın (Adım 2) |
| `no such file or directory: sftpgo` | Adım 2'yi (binary derleme) yapın |
| `glob failed: ./man1/*` | Adım 3'ü (darwin binary ile doc üretme) yapın |
| `mkdir: cannot create directory 'dist': File exists` | Adım 4'ü (eski dist temizleme) yapın |
| `SIGSEGV` / `taggedPointerPack` | Docker'da binary çalıştırmayın; sadece nfpm kullanın |
| `go.mod requires go >= 1.25.0` | Mac'te Go 1.25+ olduğunu `go version` ile doğrulayın |

---

## Tekrar Build için Özet Komutlar

```bash
# 1. Binary derle (SQLite destekli)
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
  CC="zig cc -target x86_64-linux-musl" \
  CXX="zig c++ -target x86_64-linux-musl" \
  go build -ldflags='-s -w -extldflags "-static"' -o sftpgo .

# 2. Docs üret (ilk seferinde veya güncellenince)
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o sftpgo_darwin . && \
  mkdir -p output/bash_completion output/man/man1 && \
  ./sftpgo_darwin gen completion bash > output/bash_completion/sftpgo && \
  ./sftpgo_darwin gen man -d output/man/man1 && \
  rm sftpgo_darwin

# 3. Temizle ve paketle
rm -rf pkgs/dist && \
docker run --rm --platform linux/amd64 \
  -v $(pwd):/sftpgo -w /sftpgo/pkgs \
  -e NFPM_ARCH=amd64 -e SFTPGO_VERSION=2.6.5-custom \
  ubuntu:22.04 \
  bash -c "apt-get update -q && apt-get install -y git curl && bash build.sh"

# 4. Sunucuya gönder ve kur
scp pkgs/dist/deb/sftpgo_2.6.5~custom-1_amd64.deb root@10.35.40.7:/tmp/
ssh root@10.35.40.7 "systemctl stop sftpgo && dpkg -i /tmp/sftpgo_*.deb && systemctl start sftpgo"
```
