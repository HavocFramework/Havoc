package spectests

import (
    "bufio"
    "bytes"
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "runtime"
    "strings"
    "testing"
)

func TestMain(m *testing.M) {
    // The test harness is an external program that also expects to have
    // hcldec built as an external program, so we'll build both into
    // temporary files in our working directory before running our tests
    // here, to ensure that we're always running a build of the latest code.
    err := build()
    if err != nil {
        fmt.Fprintf(os.Stderr, "%s\n", err.Error())
        os.Exit(1)
    }

    // Now we can run the tests
    os.Exit(m.Run())
}

func build() error {
    err := goBuild("Havoc/pkg/profile/yaotl/cmd/hcldec", "tmp_hcldec")
    if err != nil {
        return fmt.Errorf("error building hcldec: %s", err)
    }

    err = goBuild("Havoc/pkg/profile/yaotl/cmd/hclspecsuite", "tmp_hclspecsuite")
    if err != nil {
        return fmt.Errorf("error building hcldec: %s", err)
    }

    return nil
}

func TestSpec(t *testing.T) {
    suiteDir := filepath.Clean("../specsuite/tests")
    harness := "./tmp_hclspecsuite"
    hcldec := "./tmp_hcldec"

    cmd := exec.Command(harness, suiteDir, hcldec)
    out, err := cmd.CombinedOutput()
    if _, isExit := err.(*exec.ExitError); err != nil && !isExit {
        t.Errorf("failed to run harness: %s", err)
    }
    failed := err != nil

    sc := bufio.NewScanner(bytes.NewReader(out))
    var lines []string
    for sc.Scan() {
        lines = append(lines, sc.Text())
    }

    i := 0
    for i < len(lines) {
        cur := lines[i]
        if strings.HasPrefix(cur, "- ") {
            testName := cur[2:]
            t.Run(testName, func(t *testing.T) {
                i++
                for i < len(lines) {
                    cur := lines[i]
                    if strings.HasPrefix(cur, "- ") || strings.HasPrefix(cur, "==") {
                        return
                    }
                    t.Error(cur)
                    i++
                }
            })
        } else {
            if !strings.HasPrefix(cur, "==") { // not the "test harness problems" report, then
                t.Log(cur)
            }
            i++
        }
    }

    if failed {
        t.Error("specsuite failed")
    }
}

func goBuild(pkg, outFile string) error {
    if runtime.GOOS == "windows" {
        outFile += ".exe"
    }

    cmd := exec.Command("go", "build", "-o", outFile, pkg)
    cmd.Stderr = os.Stderr
    cmd.Stdout = os.Stdout
    return cmd.Run()
}
