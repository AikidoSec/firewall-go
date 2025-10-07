export PATH := $(HOME)/go/bin:$(PATH)

.PHONY: setup
setup: install_protoc go_setup

.PHONY: go_setup
go_setup:
	@echo "• Installing go protobuf libs"
	@go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	@go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

.PHONY: install_protoc
install_protoc:
	@echo "• Determining the package manager..."
	@if [ -f /etc/debian_version ]; then \
		echo "• Detected a Debian-based distribution."; \
		echo "• Installing protoc using apt..."; \
		sudo apt-get update; \
		sudo apt-get install -y protobuf-compiler protobuf-compiler-grpc; \
		echo "• Installation complete! You can verify by running 'protoc --version'."; \
		exit 0; \
	elif [ -f /etc/fedora-release ]; then \
		echo "• Detected a Fedora-based distribution."; \
		echo "• Installing protoc using dnf..."; \
		sudo dnf install -y protobuf-compiler; \
		echo "• Installation complete! You can verify by running 'protoc --version'."; \
		exit 0; \
	else \
		echo "• Unsupported distribution. Please install protoc manually (make install_protoc_manual)."; \
	fi

PROTOC_VERSION = 21.12

.PHONY: install_protoc_manual
install_protoc_manual:
	@echo "• Downloading protoc version $(PROTOC_VERSION)..."
	@wget https://github.com/protocolbuffers/protobuf/releases/download/v$(PROTOC_VERSION)/protoc-$(PROTOC_VERSION)-linux-x86_64.zip
	@echo "• Unzipping protoc..."
	@unzip protoc-$(PROTOC_VERSION)-linux-x86_64.zip -d protoc
	@echo "• Moving protoc binary and include files..."
	@sudo mv protoc/bin/protoc /usr/local/bin/
	@sudo mv protoc/include/* /usr/local/include/
	@echo "• Cleaning up..."
	@rm -rf protoc protoc-$(PROTOC_VERSION)-linux-x86_64.zip
	@echo "• Installation complete! You can verify by running 'protoc --version'."
