ifndef VERBOSE
.SILENT:
endif

# main build target. compiles the teamserver and client
all: ts-build client-build

# teamserver building target
ts-build:
	@ ./teamserver/Install.sh
	@ make -C teamserver ts-build

dev-ts-compile:
	@ make -C teamserver dev-ts-compile

ts-cleanup: 
	@ make -C teamserver clean

# client building and cleanup targets 
client-build: 
	@ make -C client

client-cleanup:
	@ make -C client clean

# cleanup target 
clean: ts-cleanup client-cleanup
	@ rm -rf payloads/Demon/.idea
