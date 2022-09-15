
ifndef FUZZ_WORK_DIR
$(error FUZZ_WORK_DIR is not set)
endif

default:
	@echo "See README.md for usage instructions"

fuzz-config: fuzz-exec-config

fuzz-exec-%: fuzz%-fuzz.zip
	go-fuzz -bin=./fuzz$*-fuzz.zip -workdir=$(FUZZ_WORK_DIR)

fuzz%-fuzz.zip: %/fuzz.go
	go-fuzz-build -x Havoc/pkg/profile/yaotl/hclwrite/fuzz/$*

tools:
	go get -u github.com/dvyukov/go-fuzz/go-fuzz
	go get -u github.com/dvyukov/go-fuzz/go-fuzz-build

clean:
	rm fuzz*-fuzz.zip

.PHONY: tools clean fuzz-config
.PRECIOUS: fuzzconfig-fuzz.zip
