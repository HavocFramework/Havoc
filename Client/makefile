MAKEFLAGS += -s

ifndef VERBOSE
.SILENT:
endif

all:
	@ rm -rf Build; mkdir Build; cd Build; cmake ..
	@ cmake --build Build

clean:
	@ rm -rf Build
	@ rm -rf ./Bin/*
	@ rm -rf ./Data/database.db

