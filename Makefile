.PHONY: test build
test:
	go test ./...
	./scripts/test-agent-skill.sh
build:
	go build -o bin/monicheck ./cmd/monicheck
