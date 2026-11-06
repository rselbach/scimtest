SERVER_BINARY := "scimtest-server"
PREFIX := "/usr/local"
BINDIR := PREFIX + "/bin"
SYSTEMD_DIR := "/etc/systemd/system"

default:
  just --list

build:
  go build -mod=readonly ./...

build-desktop-linux application_profile_id:
  mkdir -p ./bin
  PKG_CONFIG="${PWD}/packaging/linux/pkg-config-webkit2gtk-4.1.sh" \
    go build -mod=readonly -tags desktop \
    -ldflags="-X=github.com/rselbach/scimtest/internal/web.tunnelApplicationProfileID={{application_profile_id}} -X=github.com/rselbach/scimtest/internal/web.tunnelReleaseProfileRequired=true" \
    -o ./bin/scimtest-desktop ./cmd/scimtest-desktop

test:
  go test -mod=readonly ./...

test-desktop-linux:
  PKG_CONFIG="${PWD}/packaging/linux/pkg-config-webkit2gtk-4.1.sh" \
    go test -mod=readonly -tags desktop ./cmd/scimtest-desktop

run:
  go run -mod=readonly ./cmd/scimtest

run-rust-desktop:
  cargo run --locked -p scimtest-desktop

run-rust-api:
  cargo run --locked -p scimtest-core --bin scimtest-rust

run-rust-server:
  cargo run --locked -p scimtest-server

test-rust:
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets --locked -- -D warnings
  GOFLAGS=-mod=readonly cargo test -p scimtest-core -p scimtest-server -p scimtest-protocol --locked
  cargo test -p scimtest-desktop --locked

run-server:
  go run -mod=readonly ./cmd/scimtest-server

build-server:
  go build -mod=readonly -o ./bin/{{SERVER_BINARY}} ./cmd/scimtest-server

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
