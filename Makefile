GO ?= go

.PHONY: build test test-race lint

build:
	CGO_ENABLED=0 $(GO) build -ldflags="-s -w -X main.version=dev" -o bin/shellguard ./cmd/shellguard

test:
	$(GO) test ./... -count=1

test-race:
	$(GO) test ./... -race -count=1

lint:
	golangci-lint run ./...
