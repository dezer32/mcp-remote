.PHONY: build test test-integration lint tidy clean

BINARY := mcp-remote

build:
	go build -o $(BINARY) .

test:
	go test -race -count=1 ./...

test-integration:
	go test -race -tags=integration -count=1 ./test/...

lint:
	go vet ./...
	@test -z "$$(gofmt -l .)" || (echo "gofmt issues:" && gofmt -l . && exit 1)

tidy:
	go mod tidy

clean:
	rm -f $(BINARY)
	rm -rf dist
