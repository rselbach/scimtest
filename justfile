SERVER_BINARY := "scimtest-server"
PREFIX := "/usr/local"
BINDIR := PREFIX + "/bin"
SYSTEMD_DIR := "/etc/systemd/system"

default:
  just --list

build:
  go build ./...

build-desktop-linux application_profile_id:
  mkdir -p ./bin
  PKG_CONFIG="${PWD}/packaging/linux/pkg-config-webkit2gtk-4.1.sh" \
    go build -tags desktop \
    -ldflags="-X=github.com/rselbach/scimtest/internal/web.tunnelApplicationProfileID={{application_profile_id}} -X=github.com/rselbach/scimtest/internal/web.tunnelReleaseProfileRequired=true" \
    -o ./bin/scimtest-desktop ./cmd/scimtest-desktop

fetch-sparkle:
  ./packaging/macos/fetch-sparkle.sh

test:
  go test ./...

test-desktop-linux:
  PKG_CONFIG="${PWD}/packaging/linux/pkg-config-webkit2gtk-4.1.sh" \
    go test -tags desktop ./cmd/scimtest-desktop

run:
  go run ./cmd/scimtest

run-server:
  go run ./cmd/scimtest-server

build-server:
  go build -o ./bin/{{SERVER_BINARY}} ./cmd/scimtest-server

deploy-server: test
  ./deploy/deploy.sh

install-server-binary: build-server
  sudo install -d -m 0755 {{BINDIR}}
  sudo install -m 0755 ./bin/{{SERVER_BINARY}} {{BINDIR}}/{{SERVER_BINARY}}

install-server-systemd:
  sudo install -d -m 0755 {{SYSTEMD_DIR}}
  sudo install -m 0644 deploy/scimtest-server.service {{SYSTEMD_DIR}}/scimtest-server.service
  sudo systemctl daemon-reload

install-server: install-server-binary install-server-systemd

enable-server:
  sudo systemctl enable scimtest-server.service

start-server:
  sudo systemctl start scimtest-server.service

restart-server:
  sudo systemctl restart scimtest-server.service

status-server:
  systemctl status scimtest-server.service
