# JSON syntax fuzzing utilities

This directory contains helper functions and corpuses that can be used to
fuzz-test the HCL JSON parser using [go-fuzz](https://github.com/dvyukov/go-fuzz).

## Work directory

`go-fuzz` needs a working directory where it can keep state as it works.  This
should ideally be in a ramdisk for efficiency, and should probably _not_ be on
an SSD to avoid thrashing it. Here's how to create a ramdisk:

### macOS

```
$ SIZE_IN_MB=1024
$ DEVICE=`hdiutil attach -nobrowse -nomount ram://$(($SIZE_IN_MB*2048))`
$ diskutil erasevolume HFS+ RamDisk $DEVICE
$ export RAMDISK=/Volumes/RamDisk
```

### Linux

```
$ mkdir /mnt/ramdisk
$ mount -t tmpfs -o size=1024M tmpfs /mnt/ramdisk
$ export RAMDISK=/mnt/ramdisk
```

## Running the fuzzer

Next, install `go-fuzz` and its build tool in your `GOPATH`:

```
$ make tools FUZZ_WORK_DIR=$RAMDISK
```

Now you can fuzz the parser:

```
$ make fuzz-config FUZZ_WORK_DIR=$RAMDISK/json-fuzz-config
```

~> Note: `go-fuzz` does not interact well with `goenv`. If you encounter build
errors where the package `go.fuzz.main` could not be found, you may need to use
a machine with a direct installation of Go.

## Understanding the result

A small number of subdirectories will be created in the work directory.

If you let `go-fuzz` run for a few minutes (the more minutes the better) it
may detect "crashers", which are inputs that caused the parser to panic. Details
about these are written to `$FUZZ_WORK_DIR/crashers`:

```
$ ls /tmp/hcl2-fuzz-config/crashers
7f5e9ec80c89da14b8b0b238ec88969f658f5a2d
7f5e9ec80c89da14b8b0b238ec88969f658f5a2d.output
7f5e9ec80c89da14b8b0b238ec88969f658f5a2d.quoted
```

The base file above (with no extension) is the input that caused a crash. The
`.output` file contains the panic stack trace, which you can use as a clue to
figure out what caused the crash.

A good first step to fixing a detected crasher is to copy the failing input
into one of the unit tests in the `hcl/json` package and see it crash there
too. After that, it's easy to re-run the test as you try to fix it. The
file with the `.quoted` extension contains a form of the input that is quoted
in Go syntax for easy copy-paste into a test case, even if the input contains
non-printable characters or other inconvenient symbols.

## Rebuilding for new Upstream Code

An archive file is created for `go-fuzz` to use on the first run of each
of the above, as a `.zip` file created in this directory. If upstream code
is changed these will need to be deleted to cause them to be rebuilt with
the latest code:

```
$ make clean
```
