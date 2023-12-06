MAKEFLAGS += -s

ifndef VERBOSE
.SILENT:
endif

all:
	@ mkdir build; cd build; cmake ..
	@ if [ -d "Modules" ]; then echo "Modules installed"; else git clone https://github.com/HavocFramework/Modules Modules; fi
	@ cmake --build build -- -j 4

clean:
	@ rm -rf build
	@ rm -rf .idea
	@ rm -rf cmake-build-debug
	@ rm -rf modules
	@ rm -rf Havoc
