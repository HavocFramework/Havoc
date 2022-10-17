MAKEFLAGS += -s

ifndef VERBOSE
.SILENT:
endif

all:
	@ mkdir Build; cd Build; cmake ..
	@ if [ -d "Modules" ]; then echo "Modules installed"; else git clone https://github.com/HavocFramework/Modules; fi
	@ cmake --build Build -- -j 4

clean:
	@ rm -rf Build
	@ rm -rf ./Bin/*
	@ rm -rf ./Data/database.db
	@ rm -rf .idea
	@ rm -rf cmake-build-debug
	@ rm -rf Havoc
	@ rm -rf Modules
