# HCL Language Test Suite

This directory contains an implementation-agnostic test suite that can be used
to verify the correct behavior not only of the HCL implementation in _this_
repository but also of possible other implementations.

The harness for running this suite -- a Go program in this directory -- uses
the `hcldec` program as a level of abstraction to avoid depending directly on
the Go implementation. As a result, other HCL implementations must also
include a version of `hcldec` in order to run this spec.

The tests defined in this suite each correspond to a detail of
[the HCL spec](../spec.md). This suite is separate from and not a
substitute for direct unit tests of a given implementation that would presumably
also exercise that implementation's own programmatic API.

To run the suite, first build the harness using Go:

```
go install Havoc/pkg/profile/yaotl/cmd/hclspecsuite
```

Then run it, passing it the directory containing the test definitions (the
"tests" subdirectory of this directory) and the path to the `hcldec` executable
to use.

For example, if working in the root of this repository and using the `hcldec`
implementation from here:

```
go install ./cmd/hcldec
hclspecsuite ./specsuite/tests $GOPATH/bin/hcldec
```

For developers working on the Go implementation of HCL from this repository,
please note that this spec suite is run as part of a normal `go test ./...`
execution for this whole repository and so does not need to be run separately.
