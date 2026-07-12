default:
  just --list

build:
  go build ./...

test:
  go test ./...

run:
  go run .

rgrok-key private_key:
  go -C ./cmd/rgrok-key run . {{quote(clean(if private_key =~ '^/' { private_key } else { invocation_directory() / private_key }))}}
