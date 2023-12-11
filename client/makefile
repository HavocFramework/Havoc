MAKEFLAGS += -s

ifndef VERBOSE
.SILENT:
endif

all:
	@ git submodule update --init --recursive
	@ mkdir -p Build; cd Build; cmake ..
	#@ if [ -d "Modules" ]; then echo "Modules installed"; else git clone --recurse-submodules https://github.com/HavocFramework/Modules Modules --single-branch --branch `git rev-parse --abbrev-ref HEAD`; fi
	@ if [ -d "Modules" ]; then echo "Modules installed"; else git clone --recurse-submodules https://github.com/HavocFramework/Modules Modules --single-branch --branch dev; fi
	@ cmake --build Build -- -j 4

clean:
	@ rm -rf Build
	@ rm -rf Bin/*
	@ rm -rf ../data/client.db
	@ rm -rf .idea
	@ rm -rf cmake-build-debug
	@ rm -rf Havoc
	@ rm -rf Modules


