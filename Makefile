# sshanity Makefile

HOST_KEY_FILE = test-keys/ssh_host_ed25519_key
# Set up the linker flags to embed the testing ssh host key into the binary
HOST_KEY_VAR = xr7.org/sshanity/server.FallbackHostKey
KEY_LD = -ldflags "-X '$(HOST_KEY_VAR)=$$(cat $(HOST_KEY_FILE))'"

LINT_ARGS =

.PHONY: build
build: CGO_ENABLED=0
build: keys
	go build -o ./bin/sshanity $(KEY_LD) ./main.go

.PHONY: lint
lint:
	golangci-lint run ./... $(LINT_ARGS)

.PHONY: test
test:
	go test ./server/...

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: clean
clean:
	go clean
	rm -rf ./bin ./test-keys

# Create a host key for testing

keys: test-keys $(HOST_KEY_FILE)

$(HOST_KEY_FILE):
	ssh-keygen -t ed25519 -f $(HOST_KEY_FILE) -N '' -C 'Testing key only, do not use anywhere else!'

test-keys:
	mkdir -p $@
