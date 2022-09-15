package fuzzconfig

import (
    "Havoc/pkg/profile/yaotl/json"
)

func Fuzz(data []byte) int {
    _, diags := json.Parse(data, "<fuzz-conf>")

    if diags.HasErrors() {
        return 0
    }

    return 1
}
