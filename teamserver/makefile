MAKEFLAGS += -s

ifndef VERBOSE
.SILENT:
endif

# teamserver building target
ts-build:
	@ echo "[*] building teamserver"
	@ GO111MODULE="on" go build -ldflags="-s -w -X cmd.VersionCommit=$(git rev-parse HEAD)" -o ../havoc main.go
	@ sudo setcap 'cap_net_bind_service=+ep' ../havoc # this allows you to run the server as a regular user

dev-ts-compile:
	@ echo "[*] compile teamserver"
	@ GO111MODULE="on" go build -ldflags="-s -w -X cmd.VersionCommit=$(git rev-parse HEAD)" -o ../havoc main.go

clean:
	@ rm -rf ../data/loot
	@ rm -rf ../data/x86_64-w64-mingw32-cross
	@ rm -rf ../data/i686-w64-mingw32-cross
	@ rm -rf ../data/teamserver.db
	@ rm -rf ../data/server.*
	@ rm -rf .idea
	@ rm -rf ../havoc
	@ rm -rf /tmp/mingw-musl-64.tgz
	@ rm -rf /tmp/mingw-musl-32.tgz
