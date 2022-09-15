
ifndef FUZZ_WORK_DIR
$(error FUZZ_WORK_DIR is not set)
endif

default:
	@echo "See README.md for usage instructions"

fuzz-config: fuzz-exec-config
fuzz-expr: fuzz-exec-expr
fuzz-template: fuzz-exec-template
fuzz-traversal: fuzz-exec-traversal

fuzz-exec-%: fuzz%-fuzz.zip
	go-fuzz -bin=./fuzz$*-fuzz.zip -workdir=$(FUZZ_WORK_DIR)

fuzz%-fuzz.zip: %/fuzz.go
	go-fuzz-build Havoc/pkg/profile/yaotl/hclsyntax/fuzz/$*

tools:
	go get -u github.com/dvyukov/go-fuzz/go-fuzz
	go get -u github.com/dvyukov/go-fuzz/go-fuzz-build

clean:
	rm fuzz*-fuzz.zip

.PHONY: tools clean fuzz-config fuzz-expr fuzz-template fuzz-traversal
.PRECIOUS: fuzzconfig-fuzz.zip fuzzexpr-fuzz.zip fuzztemplate-fuzz.zip fuzztraversal-fuzz.zip
