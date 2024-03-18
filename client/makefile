MAKEFLAGS += -s

ifndef VERBOSE
.SILENT:
endif

BRANCH := $(shell git rev-parse --abbrev-ref HEAD)

# Check the value of BRANCH and set a target accordingly
ifeq ($(BRANCH), main)
    TARGET_BRANCH := main
else ifeq ($(BRANCH), dev)
    TARGET_BRANCH := dev
else
    TARGET_BRANCH := dev
endif


all:
	@ git submodule update --init --recursive
	@ mkdir -p Build; cd Build; cmake ..
	@ if [ -d "Modules" ]; then echo "Modules installed"; else git clone --recurse-submodules https://github.com/HavocFramework/Modules Modules --single-branch --branch $(TARGET_BRANCH); fi
	@ cmake --build Build -- -j 4

clean:
	@ rm -rf Build
	@ rm -rf ../data/client.db
	@ rm -rf .idea
	@ rm -rf cmake-build-debug
	@ rm -rf Havoc
	@ rm -rf Modules


