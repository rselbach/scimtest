SERVER_BINARY := "scimtest-server"
PREFIX := "/usr/local"
BINDIR := PREFIX + "/bin"
SYSTEMD_DIR := "/etc/systemd/system"

default:
  just --list

build:
  cargo build --locked --workspace

build-desktop-linux application_profile_id:
  SCIMTEST_APPLICATION_PROFILE_ID="{{application_profile_id}}" \
    ./packaging/rust/build-desktop.sh bin/scimtest-desktop 0.0.0 deb

test:
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets --locked -- -D warnings
  cargo test --workspace --locked

test-desktop-linux:
  cargo test --locked -p scimtest-desktop

run:
  cargo run --locked -p scimtest-desktop

run-api:
  cargo run --locked -p scimtest-core --bin scimtest

run-server:
  cargo run --locked -p scimtest-server

build-server:
  cargo build --locked --release -p scimtest-server
  mkdir -p ./bin
  install -m 0755 "${CARGO_TARGET_DIR:-target}/release/scimtest-server" ./bin/{{SERVER_BINARY}}

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
