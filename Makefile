.PHONY: build test vet fmt check clean

build:
	go build -o wcdscan ./cmd/wcdscan

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w ./cmd ./internal

check: fmt test vet build

clean:
	rm -f wcdscan wcdscan.exe
	rm -rf dist reports
