BINARY = netmon
SRC    = main.go
DIST   = dist

.PHONY: \
	all \
	macos macos-x64 macos-arm64 \
	linux linux-all linux-x64 linux-arm64 linux-arm \
	clean


all: macos linux-all

# --- macOS ---
macos: macos-x64 macos-arm64

macos-x64:
	@mkdir -p $(DIST)
	GOOS=darwin GOARCH=amd64 go build -o $(DIST)/$(BINARY)_darwin_x64 $(SRC)

macos-arm64:
	@mkdir -p $(DIST)
	GOOS=darwin GOARCH=arm64 go build -o $(DIST)/$(BINARY)_darwin_arm64 $(SRC)


# --- Linux ---
linux: linux-all

linux-all: linux-x64 linux-arm64 linux-arm

linux-x64:
	@mkdir -p $(DIST)
	GOOS=linux GOARCH=amd64 go build -o $(DIST)/$(BINARY)_linux_x64 $(SRC)

linux-arm64:
	@mkdir -p $(DIST)
	GOOS=linux GOARCH=arm64 go build -o $(DIST)/$(BINARY)_linux_arm64 $(SRC)

linux-arm:
	@mkdir -p $(DIST)
	GOOS=linux GOARCH=arm GOARM=7 go build -o $(DIST)/$(BINARY)_linux_arm $(SRC)

clean:
	rm -rf $(DIST)
