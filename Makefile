BINARY=ghostenv
HELPER=ghostenv-keychain
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

.PHONY: build build-helper clean test install

build: build-helper
	go build -ldflags "-s -w -X main.version=$(VERSION)" -o $(BINARY) ./cmd/ghostenv/

build-helper:
ifeq ($(shell uname),Darwin)
	swiftc -O -o $(HELPER) internal/keychain/helper/main.swift \
		-framework Security -framework LocalAuthentication
endif

test:
	go test ./... -v

clean:
	rm -f $(BINARY) $(HELPER)

install: build
	cp $(BINARY) /usr/local/bin/
ifeq ($(shell uname),Darwin)
	cp $(HELPER) /usr/local/bin/
endif
