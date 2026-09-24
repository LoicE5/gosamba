.PHONY: build build-darwin-arm64 build-darwin-amd64 test test-race test-e2e fmt vet tidy clean e2e-deps download

download:
	go mod download

e2e-deps:
	apt-get install -y smbclient

build:
	go build -o gosamba ./cmd/gosamba

build-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build -o gosamba-darwin-arm64 ./cmd/gosamba

build-darwin-amd64:
	GOOS=darwin GOARCH=amd64 go build -o gosamba-darwin-amd64 ./cmd/gosamba

test:
	go test ./...

test-race:
	go test -race ./...

# The smbclient-driven end-to-end tests are gated behind a build tag; without
# it `make test` skips all of them. Requires `make e2e-deps` first.
test-e2e:
	go test -race -tags smbclient_e2e ./...

fmt:
	go fmt ./...

vet:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -f gosamba
