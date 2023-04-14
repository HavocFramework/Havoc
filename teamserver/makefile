GOCMD	= go
GOBUILD	= GO111MODULE="on" $(GOCMD) build -ldflags="-s -w -X cmd.VersionCommit=$(git rev-parse HEAD)" -o ./teamserver main.go

ifndef VERBOSE
.SILENT:
endif

all:
	$(GOBUILD)

clean:
	rm -rf ./bin
	rm -rf ./data/loot
	rm -rf ./data/x86_64-w64-mingw32-cross 
	rm -rf ./data/havoc.db
	rm -rf .idea
	rm -rf ./teamserver
