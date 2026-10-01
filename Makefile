VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test race lint bench bench-hook e2e vault-test fuzz cover clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o claudeshield ./cmd/claudeshield

test:
	go test ./...

race:
	go test -race -count=1 ./...

lint:
	gofmt -l . | (! grep .) || (echo "gofmt needed on the files above" && exit 1)
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...

# In-process throughput of the detector.
bench:
	go test -run '^$$' -bench . -benchtime 20x ./internal/detect/

# Wall-clock cost of one hook process, as Claude Code pays it.
bench-hook: build
	python3 scripts/bench-hook.py ./claudeshield 50

# Drives the real Claude Code CLI (needs a logged-in `claude`; uses a little Haiku usage).
e2e:
	./scripts/e2e.sh

# Creates, attaches and detaches real encrypted disk images (macOS only).
vault-test:
	CLAUDESHIELD_HDIUTIL_TESTS=1 go test -count=1 -run RealImage -v ./internal/vault/

fuzz:
	go test -run '^$$' -fuzz FuzzFind -fuzztime 30s ./internal/detect/
	go test -run '^$$' -fuzz FuzzRoundTrip -fuzztime 30s ./internal/tokenmap/
	go test -run '^$$' -fuzz FuzzAnalyzeShell -fuzztime 30s ./internal/egress/

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

clean:
	rm -f claudeshield coverage.out
