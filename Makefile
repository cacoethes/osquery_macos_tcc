APP_NAME := osquery-macos-tcc
DEBUG_APP_NAME := osquery-macos-tcc-debug
BUILD_DIR := build
DEBUG ?= false

.PHONY: all clean build debug

all: build

build:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -ldflags="-X main.DEBUG=$(DEBUG)" -o $(BUILD_DIR)/$(APP_NAME) main.go
	chmod 700 $(BUILD_DIR)/$(APP_NAME)

debug:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -ldflags="-X main.DEBUG=true" -o $(BUILD_DIR)/$(DEBUG_APP_NAME) main.go
	chmod 700 $(BUILD_DIR)/$(DEBUG_APP_NAME)

clean:
	rm -rf $(BUILD_DIR)
