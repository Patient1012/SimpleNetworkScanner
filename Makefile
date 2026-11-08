BINARY  := netscan
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build run test vet fmt integration install clean

all: build

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) .

run:
	go run .

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

integration:
	NETSCAN_INTEGRATION=1 go test -count=1 ./internal/scan -run TestIntegrationScan -v

install:
	go install -trimpath -ldflags "$(LDFLAGS)" .

clean:
	rm -f $(BINARY)
