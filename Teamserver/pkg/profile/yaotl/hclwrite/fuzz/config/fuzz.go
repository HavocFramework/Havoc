package fuzzconfig

import (
    "io/ioutil"

    "Havoc/pkg/profile/yaotl"
    "Havoc/pkg/profile/yaotl/hclwrite"
)

func Fuzz(data []byte) int {
    file, diags := hclwrite.ParseConfig(data, "<fuzz-conf>", hcl.Pos{Line: 1, Column: 1})

    if diags.HasErrors() {
        return 0
    }

    _, err := file.WriteTo(ioutil.Discard)

    if err != nil {
        return 0
    }

    return 1
}
