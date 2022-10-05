GOCMD		    = go
BINARY_NAME	= teamserver
GOBUILD		  = GO111MODULE="on" $(GOCMD) build -ldflags="-s -w" -o ./$(BINARY_NAME) main.go

ifndef VERBOSE
.SILENT:
endif

all:
		echo [*] Compiling....
		$(GOBUILD)
		echo [+] Finished

clean:
		rm -rf ./bin
		rm -rf ./data/loot
		rm -rf .idea
		rm -rf ./teamserver
