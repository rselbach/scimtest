SERVER_BINARY := "scimtest-server"
PREFIX := "/usr/local"
BINDIR := PREFIX + "/bin"
SYSTEMD_DIR := "/etc/systemd/system"

default:
  just --list

build:
  go build ./...

test:
  go test ./...

run:
  go run ./cmd/scimtest

run-server:
  go run ./cmd/scimtest-server

build-server:
  go build -o ./bin/{{SERVER_BINARY}} ./cmd/scimtest-server

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

application-seed private_key:
  go -C ./cmd/application-seed run . {{quote(clean(if private_key =~ '^/' { private_key } else { invocation_directory() / private_key }))}}
